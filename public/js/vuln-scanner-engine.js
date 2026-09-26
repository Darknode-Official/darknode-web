// Darknode Vulnerability Scanner & Assessment Engine
// For AUTHORIZED penetration testing and security education ONLY.
"use strict";

// ═══════════════════════════════════════════════════════════════
// SECTION 1: HTTP FINGERPRINTING ENGINE
// ═══════════════════════════════════════════════════════════════

export function fingerprintServer(headers) {
  const h = {};
  if (typeof headers === "string") {
    for (const line of headers.split("\n")) {
      const idx = line.indexOf(":");
      if (idx > 0) h[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  } else {
    for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
  }

  const result = { server: null, version: null, technology: [], os: null, confidence: 0, raw: h };

  const serverHeader = h["server"] || "";
  if (serverHeader) {
    result.confidence += 40;
    const serverPatterns = [
      { re: /Apache\/?([\d.]+)?/i, name: "Apache", extract: 1 },
      { re: /nginx\/?([\d.]+)?/i, name: "nginx", extract: 1 },
      { re: /Microsoft-IIS\/?([\d.]+)?/i, name: "IIS", extract: 1 },
      { re: /LiteSpeed/i, name: "LiteSpeed" },
      { re: /cloudflare/i, name: "Cloudflare" },
      { re: /openresty\/?([\d.]+)?/i, name: "OpenResty", extract: 1 },
      { re: /Caddy/i, name: "Caddy" },
      { re: /Kestrel/i, name: "Kestrel (.NET)" },
      { re: /gunicorn\/?([\d.]+)?/i, name: "Gunicorn", extract: 1 },
      { re: /uvicorn/i, name: "Uvicorn" },
      { re: /Jetty\/?([\d.]+)?/i, name: "Jetty", extract: 1 },
      { re: /Tomcat\/?([\d.]+)?/i, name: "Tomcat", extract: 1 },
      { re: /WildFly\/?([\d.]+)?/i, name: "WildFly", extract: 1 },
      { re: /Cowboy/i, name: "Cowboy (Erlang)" },
      { re: /Werkzeug\/?([\d.]+)?/i, name: "Werkzeug (Flask)", extract: 1 },
      { re: /thin/i, name: "Thin (Ruby)" },
      { re: /Puma/i, name: "Puma (Ruby)" },
      { re: /Unicorn/i, name: "Unicorn (Ruby)" },
      { re: /lighttpd\/?([\d.]+)?/i, name: "lighttpd", extract: 1 },
      { re: /AmazonS3/i, name: "Amazon S3" },
      { re: /Google Frontend/i, name: "Google Frontend" },
      { re: /gws/i, name: "Google Web Server" },
      { re: /AkamaiGHost/i, name: "Akamai" },
      { re: /Varnish/i, name: "Varnish Cache" },
      { re: /Tengine\/?([\d.]+)?/i, name: "Tengine", extract: 1 },
    ];
    for (const p of serverPatterns) {
      const m = serverHeader.match(p.re);
      if (m) {
        result.server = p.name;
        if (p.extract && m[p.extract]) result.version = m[p.extract];
        break;
      }
    }
    if (!result.server) result.server = serverHeader;
  }

  const poweredBy = h["x-powered-by"] || "";
  if (poweredBy) {
    result.confidence += 20;
    const techPatterns = [
      { re: /PHP\/?([\d.]+)?/i, name: "PHP", extract: 1 },
      { re: /ASP\.NET/i, name: "ASP.NET" },
      { re: /Express/i, name: "Express.js" },
      { re: /Next\.js/i, name: "Next.js" },
      { re: /Nuxt/i, name: "Nuxt.js" },
      { re: /Django/i, name: "Django" },
      { re: /Flask/i, name: "Flask" },
      { re: /Rails/i, name: "Ruby on Rails" },
      { re: /Servlet/i, name: "Java Servlet" },
      { re: /Spring/i, name: "Spring Framework" },
      { re: /Laravel/i, name: "Laravel" },
      { re: /Symfony/i, name: "Symfony" },
      { re: /CakePHP/i, name: "CakePHP" },
      { re: /CodeIgniter/i, name: "CodeIgniter" },
      { re: /Phusion Passenger/i, name: "Phusion Passenger" },
      { re: /JBoss/i, name: "JBoss" },
      { re: /PleskLin/i, name: "Plesk (Linux)" },
      { re: /PleskWin/i, name: "Plesk (Windows)" },
    ];
    for (const p of techPatterns) {
      const m = poweredBy.match(p.re);
      if (m) {
        const tech = { name: p.name };
        if (p.extract && m[p.extract]) tech.version = m[p.extract];
        result.technology.push(tech);
      }
    }
    if (!result.technology.length) result.technology.push({ name: poweredBy });
  }

  if (h["x-aspnet-version"]) {
    result.technology.push({ name: "ASP.NET", version: h["x-aspnet-version"] });
    result.os = "Windows";
    result.confidence += 15;
  }
  if (h["x-aspnetmvc-version"]) {
    result.technology.push({ name: "ASP.NET MVC", version: h["x-aspnetmvc-version"] });
  }

  const osHints = {
    "Win32": "Windows", "Win64": "Windows", "Unix": "Unix/Linux",
    "Ubuntu": "Ubuntu Linux", "Debian": "Debian Linux", "CentOS": "CentOS Linux",
    "Red Hat": "RHEL", "FreeBSD": "FreeBSD",
  };
  for (const [hint, os] of Object.entries(osHints)) {
    if (serverHeader.includes(hint)) { result.os = os; result.confidence += 10; break; }
  }

  if (h["x-amzn-requestid"] || h["x-amz-request-id"]) result.technology.push({ name: "AWS" });
  if (h["x-goog-generation"]) result.technology.push({ name: "Google Cloud Storage" });
  if (h["cf-ray"]) result.technology.push({ name: "Cloudflare CDN" });
  if (h["x-fastly-request-id"]) result.technology.push({ name: "Fastly CDN" });
  if (h["x-vercel-id"]) result.technology.push({ name: "Vercel" });
  if (h["x-netlify-request-id"]) result.technology.push({ name: "Netlify" });
  if (h["x-firebase-hosting"]) result.technology.push({ name: "Firebase Hosting" });
  if (h["fly-request-id"]) result.technology.push({ name: "Fly.io" });
  if (h["x-render-origin-server"]) result.technology.push({ name: "Render" });
  if (h["x-railway-request-id"]) result.technology.push({ name: "Railway" });

  return result;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 2: CMS DETECTION
// ═══════════════════════════════════════════════════════════════

export function detectCMS(html, headers = {}) {
  const h = typeof headers === "string" ? {} : headers;
  const results = [];

  const checks = [
    {
      name: "WordPress",
      html: [/wp-content/i, /wp-includes/i, /wp-json/i, /xmlrpc\.php/i, /<meta name="generator" content="WordPress[\s\d.]*"/i, /\/wp-login\.php/i, /\/wp-admin/i],
      headers: { "x-pingback": /xmlrpc\.php/i, "link": /wp-json/i },
      paths: ["/wp-login.php", "/wp-admin/", "/wp-content/", "/xmlrpc.php", "/wp-json/wp/v2/"],
      version: /<meta name="generator" content="WordPress ([\d.]+)"/i,
    },
    {
      name: "Drupal",
      html: [/Drupal/i, /sites\/default\/files/i, /drupal\.js/i, /node\/\d+/i, /<meta name="Generator" content="Drupal/i],
      headers: { "x-drupal-cache": /./, "x-generator": /Drupal/i },
      paths: ["/user/login", "/admin/", "/sites/default/", "/core/misc/drupal.js"],
      version: /<meta name="Generator" content="Drupal ([\d.]+)/i,
    },
    {
      name: "Joomla",
      html: [/Joomla!/i, /\/media\/jui/i, /\/components\/com_/i, /\/administrator/i, /<meta name="generator" content="Joomla!/i],
      headers: {},
      paths: ["/administrator/", "/components/", "/media/jui/"],
      version: /<meta name="generator" content="Joomla! ([\d.]+)/i,
    },
    {
      name: "Shopify",
      html: [/cdn\.shopify\.com/i, /Shopify\.theme/i, /myshopify\.com/i],
      headers: { "x-shopify-stage": /./ },
      paths: [],
    },
    {
      name: "Wix",
      html: [/wix\.com/i, /X-Wix/i, /static\.wixstatic\.com/i],
      headers: { "x-wix-request-id": /./ },
      paths: [],
    },
    {
      name: "Squarespace",
      html: [/squarespace\.com/i, /sqsp/i, /static1\.squarespace\.com/i],
      headers: {},
      paths: [],
    },
    {
      name: "Ghost",
      html: [/<meta name="generator" content="Ghost/i, /ghost-api/i],
      headers: { "x-ghost-cache-status": /./ },
      paths: ["/ghost/api/"],
      version: /<meta name="generator" content="Ghost ([\d.]+)/i,
    },
    {
      name: "Magento",
      html: [/Mage\.Cookies/i, /\/skin\/frontend/i, /\/media\/catalog/i, /Magento/i],
      headers: { "x-magento-vary": /./ },
      paths: ["/admin/", "/skin/frontend/", "/downloader/"],
    },
    {
      name: "Django",
      html: [/csrfmiddlewaretoken/i, /django/i, /__admin__/i],
      headers: {},
      paths: ["/admin/"],
    },
    {
      name: "Ruby on Rails",
      html: [/csrf-token/i, /rails/i, /authenticity_token/i],
      headers: { "x-runtime": /[\d.]+/, "x-request-id": /[a-f0-9-]{36}/i },
      paths: [],
    },
    {
      name: "Laravel",
      html: [/laravel_session/i, /XSRF-TOKEN/i],
      headers: {},
      paths: [],
    },
    {
      name: "Next.js",
      html: [/__next/i, /_next\/static/i, /__NEXT_DATA__/i],
      headers: { "x-nextjs-cache": /./, "x-powered-by": /Next\.js/i },
      paths: ["/_next/"],
    },
    {
      name: "Nuxt.js",
      html: [/__nuxt/i, /_nuxt\//i, /nuxt/i],
      headers: {},
      paths: ["/_nuxt/"],
    },
    {
      name: "Hugo",
      html: [/<meta name="generator" content="Hugo/i],
      headers: {},
      version: /<meta name="generator" content="Hugo ([\d.]+)/i,
    },
    {
      name: "Gatsby",
      html: [/gatsby/i, /___gatsby/i, /page-data/i],
      headers: { "x-gatsby-cache": /./ },
      paths: ["/page-data/"],
    },
  ];

  for (const cms of checks) {
    let score = 0;
    let version = null;
    const evidence = [];

    for (const re of cms.html) {
      if (re.test(html)) { score += 25; evidence.push("HTML: " + re.source.slice(0, 40)); }
    }
    for (const [header, re] of Object.entries(cms.headers)) {
      const val = h[header.toLowerCase()];
      if (val && re.test(val)) { score += 30; evidence.push("Header: " + header); }
    }
    if (cms.version) {
      const m = html.match(cms.version);
      if (m) { version = m[1]; score += 20; }
    }

    if (score >= 25) {
      results.push({
        cms: cms.name,
        version,
        confidence: Math.min(100, score),
        evidence,
        knownPaths: cms.paths,
      });
    }
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}

// ═══════════════════════════════════════════════════════════════
// SECTION 3: TECHNOLOGY STACK DETECTION
// ═══════════════════════════════════════════════════════════════

export function detectTechStack(html, headers = {}) {
  const stack = { frameworks: [], libraries: [], analytics: [], cdns: [], waf: [], misc: [] };

  const jsFrameworks = [
    { re: /react/i, name: "React", category: "frameworks" },
    { re: /angular/i, name: "Angular", category: "frameworks" },
    { re: /vue\.js|vuejs|Vue\(/i, name: "Vue.js", category: "frameworks" },
    { re: /svelte/i, name: "Svelte", category: "frameworks" },
    { re: /ember/i, name: "Ember.js", category: "frameworks" },
    { re: /backbone/i, name: "Backbone.js", category: "frameworks" },
    { re: /jquery|jQuery/i, name: "jQuery", category: "libraries" },
    { re: /lodash|_\./i, name: "Lodash", category: "libraries" },
    { re: /bootstrap/i, name: "Bootstrap", category: "libraries" },
    { re: /tailwind/i, name: "Tailwind CSS", category: "libraries" },
    { re: /materialize/i, name: "Materialize", category: "libraries" },
    { re: /bulma/i, name: "Bulma", category: "libraries" },
    { re: /foundation/i, name: "Foundation", category: "libraries" },
    { re: /three\.js|THREE\./i, name: "Three.js", category: "libraries" },
    { re: /d3\.js|d3\./i, name: "D3.js", category: "libraries" },
    { re: /chart\.js/i, name: "Chart.js", category: "libraries" },
    { re: /moment\.js|moment\(/i, name: "Moment.js", category: "libraries" },
    { re: /axios/i, name: "Axios", category: "libraries" },
    { re: /socket\.io/i, name: "Socket.IO", category: "libraries" },
    { re: /alpine/i, name: "Alpine.js", category: "frameworks" },
    { re: /htmx/i, name: "HTMX", category: "frameworks" },
    { re: /stimulus/i, name: "Stimulus", category: "frameworks" },
    { re: /turbo/i, name: "Turbo", category: "frameworks" },
    { re: /lit-element|lit-html/i, name: "Lit", category: "frameworks" },
  ];

  const analyticsPatterns = [
    { re: /google-analytics|gtag|GA_TRACKING_ID|ua-\d/i, name: "Google Analytics" },
    { re: /googletagmanager/i, name: "Google Tag Manager" },
    { re: /facebook\.net\/.*fbevents|fbq\(/i, name: "Facebook Pixel" },
    { re: /hotjar/i, name: "Hotjar" },
    { re: /segment\.com|analytics\.js/i, name: "Segment" },
    { re: /mixpanel/i, name: "Mixpanel" },
    { re: /amplitude/i, name: "Amplitude" },
    { re: /heap-\d|heap\.load/i, name: "Heap" },
    { re: /plausible/i, name: "Plausible" },
    { re: /matomo|piwik/i, name: "Matomo" },
    { re: /clarity\.ms/i, name: "Microsoft Clarity" },
    { re: /posthog/i, name: "PostHog" },
    { re: /intercom/i, name: "Intercom" },
    { re: /crisp\.chat/i, name: "Crisp" },
    { re: /tawk\.to/i, name: "Tawk.to" },
    { re: /zendesk/i, name: "Zendesk" },
    { re: /drift/i, name: "Drift" },
    { re: /hubspot/i, name: "HubSpot" },
    { re: /sentry/i, name: "Sentry" },
    { re: /datadog/i, name: "Datadog" },
    { re: /newrelic/i, name: "New Relic" },
    { re: /logrocket/i, name: "LogRocket" },
  ];

  const cdnPatterns = [
    { re: /cloudflare/i, name: "Cloudflare" },
    { re: /cdn\.jsdelivr\.net/i, name: "jsDelivr" },
    { re: /cdnjs\.cloudflare\.com/i, name: "cdnjs" },
    { re: /unpkg\.com/i, name: "unpkg" },
    { re: /maxcdn|stackpath/i, name: "StackPath/MaxCDN" },
    { re: /akamai/i, name: "Akamai" },
    { re: /fastly/i, name: "Fastly" },
    { re: /cloudfront/i, name: "AWS CloudFront" },
    { re: /googleapis\.com/i, name: "Google CDN" },
    { re: /azureedge\.net/i, name: "Azure CDN" },
  ];

  const wafPatterns = [
    { re: /cloudflare/i, header: "server", name: "Cloudflare WAF" },
    { re: /mod_security|NOYB/i, header: "server", name: "ModSecurity" },
    { re: /incapsula|imperva/i, header: "x-cdn", name: "Imperva/Incapsula" },
    { re: /sucuri/i, header: "x-sucuri-id", name: "Sucuri WAF" },
    { re: /barracuda/i, header: "server", name: "Barracuda WAF" },
    { re: /f5|big-ip/i, header: "server", name: "F5 BIG-IP" },
    { re: /awselb|aws/i, header: "server", name: "AWS WAF/ALB" },
    { re: /akamai/i, header: "server", name: "Akamai WAF" },
    { re: /edgecast/i, header: "server", name: "Edgecast/Verizon" },
    { re: /ddos-guard/i, header: "server", name: "DDoS-Guard" },
  ];

  for (const p of jsFrameworks) {
    if (p.re.test(html)) stack[p.category].push(p.name);
  }
  for (const p of analyticsPatterns) {
    if (p.re.test(html)) stack.analytics.push(p.name);
  }
  for (const p of cdnPatterns) {
    if (p.re.test(html)) stack.cdns.push(p.name);
  }

  const h = typeof headers === "object" ? headers : {};
  for (const p of wafPatterns) {
    const val = h[p.header] || "";
    if (p.re.test(val)) stack.waf.push(p.name);
  }

  // Deduplicate
  for (const key of Object.keys(stack)) {
    stack[key] = [...new Set(stack[key])];
  }

  return stack;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 4: SECURITY HEADER ANALYZER
// ═══════════════════════════════════════════════════════════════

export function analyzeSecurityHeaders(headers) {
  const h = {};
  if (typeof headers === "string") {
    for (const line of headers.split("\n")) {
      const idx = line.indexOf(":");
      if (idx > 0) h[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx + 1).trim();
    }
  } else {
    for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = v;
  }

  const checks = [
    {
      header: "strict-transport-security",
      name: "HTTP Strict Transport Security (HSTS)",
      severity: "high",
      recommendation: "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
      validate: (v) => {
        if (!v) return { present: false, grade: "F" };
        const maxAge = parseInt((v.match(/max-age=(\d+)/i) || [])[1] || "0");
        const subdomains = /includeSubDomains/i.test(v);
        const preload = /preload/i.test(v);
        let grade = "A";
        if (maxAge < 31536000) grade = "B";
        if (maxAge < 2592000) grade = "C";
        if (!subdomains) grade = grade > "B" ? grade : "B";
        return { present: true, grade, maxAge, subdomains, preload };
      }
    },
    {
      header: "content-security-policy",
      name: "Content Security Policy (CSP)",
      severity: "high",
      recommendation: "Add: Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'",
      validate: (v) => {
        if (!v) return { present: false, grade: "F" };
        let grade = "A";
        const issues = [];
        if (v.includes("'unsafe-inline'") && v.includes("script-src")) { grade = "C"; issues.push("unsafe-inline in script-src"); }
        if (v.includes("'unsafe-eval'")) { grade = "C"; issues.push("unsafe-eval allowed"); }
        if (v.includes("*") && !v.includes("*.")) { grade = "D"; issues.push("wildcard source"); }
        if (!v.includes("default-src")) { issues.push("missing default-src"); if (grade < "B") grade = "B"; }
        return { present: true, grade, issues, directives: v.split(";").map(d => d.trim()).filter(Boolean) };
      }
    },
    {
      header: "x-frame-options",
      name: "X-Frame-Options",
      severity: "medium",
      recommendation: "Add: X-Frame-Options: DENY (or SAMEORIGIN)",
      validate: (v) => {
        if (!v) return { present: false, grade: "F" };
        const upper = v.toUpperCase().trim();
        if (upper === "DENY") return { present: true, grade: "A", value: upper };
        if (upper === "SAMEORIGIN") return { present: true, grade: "A", value: upper };
        if (upper.startsWith("ALLOW-FROM")) return { present: true, grade: "B", value: upper };
        return { present: true, grade: "C", value: upper, note: "Invalid value" };
      }
    },
    {
      header: "x-content-type-options",
      name: "X-Content-Type-Options",
      severity: "medium",
      recommendation: "Add: X-Content-Type-Options: nosniff",
      validate: (v) => {
        if (!v) return { present: false, grade: "F" };
        return { present: true, grade: v.trim().toLowerCase() === "nosniff" ? "A" : "C" };
      }
    },
    {
      header: "referrer-policy",
      name: "Referrer-Policy",
      severity: "low",
      recommendation: "Add: Referrer-Policy: strict-origin-when-cross-origin",
      validate: (v) => {
        if (!v) return { present: false, grade: "D" };
        const safe = ["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"];
        return { present: true, grade: safe.includes(v.trim().toLowerCase()) ? "A" : "B" };
      }
    },
    {
      header: "permissions-policy",
      name: "Permissions-Policy",
      severity: "low",
      recommendation: "Add: Permissions-Policy: camera=(), microphone=(), geolocation=()",
      validate: (v) => {
        if (!v) return { present: false, grade: "D" };
        return { present: true, grade: "A", directives: v.split(",").map(d => d.trim()) };
      }
    },
    {
      header: "x-xss-protection",
      name: "X-XSS-Protection",
      severity: "info",
      recommendation: "Modern browsers ignore this; rely on CSP instead. If set, use: X-XSS-Protection: 0",
      validate: (v) => {
        if (!v) return { present: false, grade: "N/A", note: "Deprecated — use CSP instead" };
        return { present: true, grade: v.trim() === "0" ? "A" : "B", note: "Deprecated header" };
      }
    },
    {
      header: "cross-origin-opener-policy",
      name: "Cross-Origin-Opener-Policy (COOP)",
      severity: "low",
      recommendation: "Add: Cross-Origin-Opener-Policy: same-origin",
      validate: (v) => {
        if (!v) return { present: false, grade: "C" };
        return { present: true, grade: v.includes("same-origin") ? "A" : "B" };
      }
    },
    {
      header: "cross-origin-resource-policy",
      name: "Cross-Origin-Resource-Policy (CORP)",
      severity: "low",
      recommendation: "Add: Cross-Origin-Resource-Policy: same-origin",
      validate: (v) => {
        if (!v) return { present: false, grade: "C" };
        return { present: true, grade: "A" };
      }
    },
    {
      header: "cross-origin-embedder-policy",
      name: "Cross-Origin-Embedder-Policy (COEP)",
      severity: "low",
      recommendation: "Add: Cross-Origin-Embedder-Policy: require-corp",
      validate: (v) => {
        if (!v) return { present: false, grade: "C" };
        return { present: true, grade: "A" };
      }
    },
  ];

  const leakyHeaders = [
    { header: "server", name: "Server version disclosure", severity: "info" },
    { header: "x-powered-by", name: "Technology disclosure", severity: "low" },
    { header: "x-aspnet-version", name: "ASP.NET version disclosure", severity: "low" },
    { header: "x-aspnetmvc-version", name: "ASP.NET MVC version disclosure", severity: "low" },
  ];

  const results = [];
  let totalScore = 0, maxScore = 0;

  for (const check of checks) {
    const val = h[check.header];
    const result = check.validate(val);
    const gradeScore = { A: 100, B: 75, C: 50, D: 25, F: 0, "N/A": 50 };
    const weight = { high: 3, medium: 2, low: 1, info: 0.5 };
    const w = weight[check.severity] || 1;
    totalScore += (gradeScore[result.grade] || 0) * w;
    maxScore += 100 * w;
    results.push({ ...check, ...result });
  }

  const leaks = [];
  for (const leak of leakyHeaders) {
    if (h[leak.header]) {
      leaks.push({ ...leak, value: h[leak.header] });
    }
  }

  const overallGrade = maxScore > 0 ? Math.round(totalScore / maxScore * 100) : 0;
  let letter;
  if (overallGrade >= 90) letter = "A";
  else if (overallGrade >= 80) letter = "B";
  else if (overallGrade >= 60) letter = "C";
  else if (overallGrade >= 40) letter = "D";
  else letter = "F";

  return { grade: letter, score: overallGrade, checks: results, leaks, total: results.length, present: results.filter(r => r.present).length };
}

// ═══════════════════════════════════════════════════════════════
// SECTION 5: COOKIE SECURITY ANALYZER
// ═══════════════════════════════════════════════════════════════

export function analyzeCookies(setCookieHeaders) {
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  return cookies.filter(Boolean).map(raw => {
    const parts = raw.split(";").map(p => p.trim());
    const [nameVal, ...attrs] = parts;
    const eqIdx = nameVal.indexOf("=");
    const name = eqIdx > 0 ? nameVal.slice(0, eqIdx).trim() : nameVal;
    const value = eqIdx > 0 ? nameVal.slice(eqIdx + 1) : "";
    const flags = {};
    for (const attr of attrs) {
      const [k, v] = attr.split("=").map(s => s.trim());
      flags[k.toLowerCase()] = v || true;
    }

    const issues = [];
    if (!flags.secure) issues.push({ severity: "high", issue: "Missing Secure flag — cookie sent over HTTP" });
    if (!flags.httponly) issues.push({ severity: "medium", issue: "Missing HttpOnly — accessible via JavaScript (XSS risk)" });
    if (!flags.samesite) issues.push({ severity: "medium", issue: "Missing SameSite — vulnerable to CSRF" });
    else if (flags.samesite.toLowerCase() === "none" && !flags.secure) {
      issues.push({ severity: "high", issue: "SameSite=None without Secure — browser will reject" });
    }
    if (flags.domain && flags.domain.startsWith(".")) {
      issues.push({ severity: "low", issue: "Domain set to wildcard — shared with subdomains" });
    }
    if (!flags.path || flags.path === "/") {
      issues.push({ severity: "info", issue: "Path=/ — cookie sent to all paths" });
    }
    if (flags["max-age"]) {
      const maxAge = parseInt(flags["max-age"]);
      if (maxAge > 31536000) issues.push({ severity: "low", issue: "Very long expiry (>1 year)" });
    }
    if (/session|token|auth|jwt|sid|csrf/i.test(name)) {
      if (!flags.httponly) issues.push({ severity: "high", issue: "Session/auth cookie without HttpOnly" });
      if (!flags.secure) issues.push({ severity: "high", issue: "Session/auth cookie without Secure" });
    }
    if (value.length > 4096) issues.push({ severity: "info", issue: "Cookie value exceeds 4KB" });

    const score = issues.length === 0 ? "A" : issues.some(i => i.severity === "high") ? "F" : issues.some(i => i.severity === "medium") ? "C" : "B";

    return { name, flags, issues, score, raw };
  });
}

// ═══════════════════════════════════════════════════════════════
// SECTION 6: SUBDOMAIN ENUMERATION WORDLIST
// ═══════════════════════════════════════════════════════════════

export const SUBDOMAIN_WORDLIST = [
  "www","mail","ftp","localhost","webmail","smtp","pop","ns1","ns2","ns3","ns4",
  "blog","dev","staging","test","api","app","admin","portal","cpanel","whm",
  "webdisk","mobile","m","wap","remote","vpn","ssl","secure","shop","store",
  "my","status","help","support","docs","wiki","forum","community","git",
  "svn","jenkins","ci","cd","build","deploy","release","demo","beta","alpha",
  "stage","stg","uat","qa","pre","preprod","sandbox","lab","labs","internal",
  "intranet","extranet","corp","corporate","office","local","private",
  "old","new","legacy","backup","bak","temp","tmp","cache","proxy","cdn",
  "media","static","assets","img","images","video","files","upload","uploads",
  "download","downloads","data","db","database","mysql","postgres","redis",
  "mongo","elastic","elasticsearch","kibana","grafana","prometheus","influx",
  "nagios","zabbix","monitor","monitoring","metrics","logs","logging",
  "sentry","alert","alerts","notify","notification","push","mq","queue",
  "rabbitmq","kafka","nats","amqp","ws","websocket","socket","realtime",
  "live","stream","streaming","rtmp","hls","dash","feed","rss","atom",
  "auth","login","sso","oauth","saml","ldap","cas","identity","iam",
  "account","accounts","user","users","profile","register","signup","signin",
  "password","reset","recovery","verify","confirm","activate","token",
  "key","keys","cert","certs","certificate","pki","ca","ocsp","crl",
  "dns","ns","nameserver","resolver","bind","unbound","dnsmasq",
  "mx","imap","pop3","exchange","owa","autodiscover","eas","activesync",
  "calendar","contacts","chat","im","xmpp","jabber","irc","slack","teams",
  "meet","zoom","video","voice","phone","sip","voip","pbx","asterisk",
  "cloud","aws","azure","gcp","gce","ec2","s3","lambda","heroku","digital",
  "ocean","do","linode","vultr","ovh","hetzner","scaleway","vercel","netlify",
  "pages","github","gitlab","bitbucket","jira","confluence","trello","asana",
  "notion","airtable","figma","sketch","adobe","canva","design","ux","ui",
  "marketing","sales","crm","erp","hr","finance","billing","invoice",
  "payment","pay","checkout","cart","order","orders","product","products",
  "catalog","inventory","warehouse","shipping","tracking","analytics",
  "stats","report","reports","dashboard","panel","console","manager",
  "control","config","configuration","settings","setup","install","wizard",
  "update","upgrade","patch","fix","hotfix","maintenance","health","ping",
  "check","heartbeat","readiness","liveness","ready","alive","info",
  "version","about","changelog","roadmap","faq","tos","terms","privacy",
  "legal","compliance","audit","security","pentest","vulnerability","bug",
  "bounty","reward","responsible","disclosure","report","abuse","spam",
  "phishing","malware","threat","scan","scanner","check","verify","validate",
  "mx1","mx2","ns5","ns6","web","web1","web2","web3","app1","app2","app3",
  "api1","api2","api3","db1","db2","db3","cache1","cache2","worker","job",
  "task","cron","scheduler","batch","queue1","queue2","lb","loadbalancer",
  "haproxy","traefik","envoy","istio","consul","vault","nomad","terraform",
  "ansible","puppet","chef","salt","docker","container","k8s","kubernetes",
  "cluster","node","master","worker1","worker2","etcd","registry","harbor",
  "nexus","artifactory","sonar","sonarqube","code","review","merge",
  "hook","webhook","callback","event","events","trigger","action","actions",
  "workflow","pipeline","stage","environment","env","dev1","dev2","test1",
  "test2","staging1","staging2","prod","production","edge","origin",
  "backend","frontend","service","services","microservice","micro","gateway",
  "ingress","egress","mesh","sidecar","proxy1","proxy2","reverse","forward",
  "redirect","rewrite","route","router","routing","balancer","failover",
  "primary","secondary","replica","standby","witness","arbiter","quorum",
  "leader","follower","master1","master2","slave","slave1","slave2",
  "read","write","sync","async","batch1","batch2","stream1","stream2",
  "ingest","etl","transform","load","extract","migrate","migration",
  "backup1","backup2","restore","archive","cold","warm","hot","tier",
  "storage","object","block","file","nfs","smb","cifs","iscsi","fc",
  "san","nas","raid","lvm","zfs","btrfs","ext4","xfs","ntfs","fat32",
].slice(0, 5000);

// ═══════════════════════════════════════════════════════════════
// SECTION 7: DIRECTORY BRUTE-FORCE WORDLIST
// ═══════════════════════════════════════════════════════════════

export const DIRECTORY_WORDLIST = [
  "/","/admin","/admin/","/administrator","/administrator/","/login","/login/",
  "/wp-admin","/wp-login.php","/wp-content","/wp-includes","/xmlrpc.php",
  "/wp-json","/wp-cron.php","/wp-config.php.bak","/wp-config.old",
  "/.git","/.git/HEAD","/.git/config","/.gitignore","/.env","/.env.local",
  "/.env.production","/.env.development","/.env.backup","/.env.old",
  "/.htaccess","/.htpasswd","/.svn","/.svn/entries","/.hg","/.bzr",
  "/.DS_Store","/Thumbs.db","/web.config","/crossdomain.xml",
  "/robots.txt","/sitemap.xml","/sitemap_index.xml","/humans.txt",
  "/security.txt","/.well-known/security.txt","/.well-known/openid-configuration",
  "/server-status","/server-info","/nginx-status","/phpinfo.php","/info.php",
  "/test.php","/debug","/debug/","/trace","/trace/","/status","/health",
  "/healthcheck","/healthz","/readyz","/livez","/metrics","/prometheus",
  "/api","/api/","/api/v1","/api/v2","/api/v3","/api/docs","/api/swagger",
  "/swagger","/swagger/","/swagger-ui","/swagger-ui.html","/swagger.json",
  "/swagger.yaml","/openapi.json","/openapi.yaml","/api-docs","/redoc",
  "/graphql","/graphiql","/graphql/console","/playground",
  "/console","/console/","/shell","/cmd","/command","/exec","/terminal",
  "/phpmyadmin","/phpMyAdmin","/pma","/adminer","/adminer.php",
  "/mysql","/myadmin","/sql","/db","/database",
  "/config","/config/","/configuration","/conf","/settings","/setup",
  "/install","/install/","/installer","/upgrade","/update",
  "/backup","/backup/","/backups","/bak","/old","/temp","/tmp","/cache",
  "/log","/logs","/error_log","/access_log","/debug.log","/app.log",
  "/test","/test/","/testing","/dev","/development","/staging",
  "/demo","/sample","/example","/prototype","/poc",
  "/cgi-bin","/cgi-bin/","/cgi","/bin","/scripts",
  "/assets","/static","/public","/uploads","/upload","/files","/media",
  "/images","/img","/css","/js","/fonts","/icons",
  "/includes","/include","/inc","/lib","/libs","/vendor","/node_modules",
  "/bower_components","/packages","/dist","/build","/target","/output",
  "/secret","/secrets","/private","/internal","/hidden",
  "/dashboard","/panel","/cpanel","/webmail","/portal","/manager",
  "/manage","/management","/monitoring","/monitor",
  "/user","/users","/profile","/account","/accounts","/register",
  "/signup","/signin","/auth","/authenticate","/oauth","/sso",
  "/logout","/signout","/forgot","/reset","/password","/recover",
  "/token","/verify","/confirm","/activate","/enable","/disable",
  "/search","/find","/query","/filter","/browse","/explore",
  "/download","/downloads","/export","/import","/migrate",
  "/report","/reports","/analytics","/stats","/statistics",
  "/help","/faq","/support","/contact","/feedback","/about",
  "/terms","/privacy","/policy","/legal","/compliance",
  "/docs","/documentation","/doc","/guide","/tutorial","/wiki",
  "/blog","/news","/press","/media","/events","/calendar",
  "/forum","/community","/discuss","/comments","/reviews",
  "/shop","/store","/cart","/checkout","/payment","/order","/orders",
  "/product","/products","/catalog","/category","/categories",
  "/invoice","/billing","/subscription","/plan","/plans","/pricing",
  "/jenkins","/ci","/cd","/build","/deploy","/release","/pipeline",
  "/git","/gitlab","/bitbucket","/jira","/confluence","/wiki",
  "/sonar","/sonarqube","/nexus","/artifactory","/registry",
  "/docker","/kubernetes","/k8s","/helm","/terraform","/ansible",
  "/vault","/consul","/nomad","/traefik","/envoy","/istio",
  "/grafana","/kibana","/prometheus","/elasticsearch","/logstash",
  "/nagios","/zabbix","/datadog","/newrelic","/sentry",
  "/redis","/memcached","/rabbitmq","/kafka","/nats","/mqtt",
  "/actuator","/actuator/health","/actuator/info","/actuator/env",
  "/actuator/beans","/actuator/mappings","/actuator/configprops",
  "/actuator/trace","/actuator/threaddump","/actuator/heapdump",
  "/jolokia","/jolokia/list","/jmx-console",
  "/.well-known/","/favicon.ico","/manifest.json","/service-worker.js",
  "/browserconfig.xml","/apple-app-site-association",
  "/__debug__","/__toolbar__","/_debug_toolbar","/_profiler",
  "/elmah.axd","/trace.axd","/glimpse.axd",
  "/server","/version","/info","/ping","/echo",
  "/wp-json/wp/v2/users","/wp-json/wp/v2/posts",
  "/feed","/rss","/atom","/sitemap",
  "/ckeditor","/tinymce","/elfinder","/filemanager",
  "/webdav","/dav","/caldav","/carddav",
].slice(0, 3000);

// ═══════════════════════════════════════════════════════════════
// SECTION 8: DEFAULT CREDENTIALS DATABASE
// ═══════════════════════════════════════════════════════════════

export const DEFAULT_CREDENTIALS = [
  { service: "SSH", user: "root", pass: "root" },
  { service: "SSH", user: "root", pass: "toor" },
  { service: "SSH", user: "root", pass: "password" },
  { service: "SSH", user: "root", pass: "123456" },
  { service: "SSH", user: "admin", pass: "admin" },
  { service: "SSH", user: "admin", pass: "password" },
  { service: "SSH", user: "user", pass: "user" },
  { service: "SSH", user: "ubuntu", pass: "ubuntu" },
  { service: "SSH", user: "pi", pass: "raspberry" },
  { service: "SSH", user: "vagrant", pass: "vagrant" },
  { service: "MySQL", user: "root", pass: "" },
  { service: "MySQL", user: "root", pass: "root" },
  { service: "MySQL", user: "root", pass: "mysql" },
  { service: "MySQL", user: "root", pass: "password" },
  { service: "MySQL", user: "admin", pass: "admin" },
  { service: "MySQL", user: "dbuser", pass: "dbpass" },
  { service: "PostgreSQL", user: "postgres", pass: "postgres" },
  { service: "PostgreSQL", user: "postgres", pass: "password" },
  { service: "PostgreSQL", user: "admin", pass: "admin" },
  { service: "MongoDB", user: "admin", pass: "admin" },
  { service: "MongoDB", user: "root", pass: "root" },
  { service: "MongoDB", user: "admin", pass: "password" },
  { service: "Redis", user: "", pass: "" },
  { service: "Redis", user: "", pass: "redis" },
  { service: "Redis", user: "", pass: "password" },
  { service: "FTP", user: "anonymous", pass: "anonymous" },
  { service: "FTP", user: "anonymous", pass: "" },
  { service: "FTP", user: "ftp", pass: "ftp" },
  { service: "FTP", user: "admin", pass: "admin" },
  { service: "Telnet", user: "admin", pass: "admin" },
  { service: "Telnet", user: "root", pass: "root" },
  { service: "Telnet", user: "user", pass: "user" },
  { service: "SNMP", user: "", pass: "public" },
  { service: "SNMP", user: "", pass: "private" },
  { service: "SNMP", user: "", pass: "community" },
  { service: "VNC", user: "", pass: "password" },
  { service: "VNC", user: "", pass: "123456" },
  { service: "VNC", user: "", pass: "" },
  { service: "Tomcat", user: "tomcat", pass: "tomcat" },
  { service: "Tomcat", user: "admin", pass: "admin" },
  { service: "Tomcat", user: "manager", pass: "manager" },
  { service: "Tomcat", user: "tomcat", pass: "s3cret" },
  { service: "Tomcat", user: "admin", pass: "password" },
  { service: "JBoss", user: "admin", pass: "admin" },
  { service: "JBoss", user: "jboss", pass: "jboss" },
  { service: "Jenkins", user: "admin", pass: "admin" },
  { service: "Jenkins", user: "admin", pass: "password" },
  { service: "WordPress", user: "admin", pass: "admin" },
  { service: "WordPress", user: "admin", pass: "password" },
  { service: "WordPress", user: "admin", pass: "wordpress" },
  { service: "Drupal", user: "admin", pass: "admin" },
  { service: "Drupal", user: "admin", pass: "password" },
  { service: "Joomla", user: "admin", pass: "admin" },
  { service: "phpMyAdmin", user: "root", pass: "" },
  { service: "phpMyAdmin", user: "root", pass: "root" },
  { service: "phpMyAdmin", user: "admin", pass: "admin" },
  { service: "Cisco", user: "admin", pass: "admin" },
  { service: "Cisco", user: "cisco", pass: "cisco" },
  { service: "Cisco", user: "admin", pass: "cisco" },
  { service: "Cisco", user: "enable", pass: "enable" },
  { service: "Fortinet", user: "admin", pass: "" },
  { service: "Fortinet", user: "admin", pass: "admin" },
  { service: "SonicWall", user: "admin", pass: "password" },
  { service: "Mikrotik", user: "admin", pass: "" },
  { service: "Ubiquiti", user: "ubnt", pass: "ubnt" },
  { service: "Ubiquiti", user: "admin", pass: "admin" },
  { service: "HP iLO", user: "Administrator", pass: "admin" },
  { service: "Dell iDRAC", user: "root", pass: "calvin" },
  { service: "Supermicro IPMI", user: "ADMIN", pass: "ADMIN" },
  { service: "Oracle", user: "sys", pass: "change_on_install" },
  { service: "Oracle", user: "system", pass: "manager" },
  { service: "Oracle", user: "scott", pass: "tiger" },
  { service: "MSSQL", user: "sa", pass: "sa" },
  { service: "MSSQL", user: "sa", pass: "" },
  { service: "MSSQL", user: "sa", pass: "password" },
  { service: "Elasticsearch", user: "elastic", pass: "changeme" },
  { service: "Grafana", user: "admin", pass: "admin" },
  { service: "Kibana", user: "elastic", pass: "changeme" },
  { service: "RabbitMQ", user: "guest", pass: "guest" },
  { service: "Nagios", user: "nagiosadmin", pass: "nagiosadmin" },
  { service: "Zabbix", user: "Admin", pass: "zabbix" },
  { service: "GitLab", user: "root", pass: "5iveL!fe" },
  { service: "Nexus", user: "admin", pass: "admin123" },
  { service: "SonarQube", user: "admin", pass: "admin" },
  { service: "Portainer", user: "admin", pass: "tryportainer" },
  { service: "Webmin", user: "admin", pass: "admin" },
  { service: "Webmin", user: "root", pass: "root" },
  { service: "pfSense", user: "admin", pass: "pfsense" },
  { service: "OPNsense", user: "root", pass: "opnsense" },
  { service: "OpenWrt", user: "root", pass: "" },
  { service: "DD-WRT", user: "root", pass: "admin" },
  { service: "Proxmox", user: "root", pass: "proxmox" },
  { service: "ESXi", user: "root", pass: "vmware" },
  { service: "vCenter", user: "administrator@vsphere.local", pass: "VMware1!" },
  { service: "Kubernetes", user: "admin", pass: "admin" },
  { service: "Docker Registry", user: "", pass: "" },
  { service: "MinIO", user: "minioadmin", pass: "minioadmin" },
  { service: "Consul", user: "", pass: "" },
  { service: "Vault", user: "root", pass: "root" },
  { service: "Rancher", user: "admin", pass: "admin" },
  { service: "ArgoCD", user: "admin", pass: "argocd-server-pod-name" },
  { service: "Airflow", user: "airflow", pass: "airflow" },
  { service: "Apache Superset", user: "admin", pass: "admin" },
  { service: "Jupyter", user: "", pass: "" },
  { service: "Jupyter", user: "", pass: "jupyter" },
];

// ═══════════════════════════════════════════════════════════════
// SECTION 9: PORT-TO-SERVICE MAPPING
// ═══════════════════════════════════════════════════════════════

export const PORT_SERVICE_MAP = {
  7:"echo",9:"discard",13:"daytime",17:"qotd",19:"chargen",20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",
  25:"smtp",37:"time",42:"nameserver",43:"whois",49:"tacacs",53:"dns",67:"dhcp-server",68:"dhcp-client",
  69:"tftp",70:"gopher",79:"finger",80:"http",81:"http-alt",88:"kerberos",110:"pop3",111:"rpcbind",
  113:"ident",119:"nntp",123:"ntp",135:"msrpc",137:"netbios-ns",138:"netbios-dgm",139:"netbios-ssn",
  143:"imap",161:"snmp",162:"snmptrap",179:"bgp",194:"irc",201:"appletalk",209:"qmtp",210:"z39.50",
  220:"imap3",389:"ldap",443:"https",445:"smb",464:"kerberos-pw",465:"smtps",500:"isakmp",
  512:"rexec",513:"rlogin",514:"syslog",515:"printer",520:"rip",523:"ibm-db2",530:"rpc",
  543:"klogin",544:"kshell",546:"dhcpv6-client",547:"dhcpv6-server",548:"afp",554:"rtsp",
  587:"submission",593:"http-rpc",631:"ipp",636:"ldaps",639:"msdp",646:"ldp",666:"doom",
  691:"msexch-routing",860:"iscsi",873:"rsync",902:"vmware-auth",989:"ftps-data",990:"ftps",
  993:"imaps",995:"pop3s",1025:"nfs-or-iis",1080:"socks",1099:"rmiregistry",1194:"openvpn",
  1214:"kazaa",1241:"nessus",1311:"dell-openmanage",1337:"waste",1433:"mssql",1434:"mssql-browser",
  1500:"vlc",1521:"oracle",1723:"pptp",1741:"cisco-phone",1812:"radius",1813:"radius-acct",
  1883:"mqtt",1900:"ssdp",2049:"nfs",2082:"cpanel",2083:"cpanel-ssl",2086:"whm",2087:"whm-ssl",
  2100:"amiganetfs",2181:"zookeeper",2222:"ssh-alt",2375:"docker",2376:"docker-ssl",
  2379:"etcd",2380:"etcd-peer",2483:"oracle-alt",2484:"oracle-alt-ssl",
  3000:"grafana/dev",3001:"nessus",3128:"squid",3260:"iscsi-target",3268:"ldap-gc",3269:"ldap-gc-ssl",
  3306:"mysql",3389:"rdp",3690:"svn",4000:"remoteanything",4040:"spark",4443:"pharos",4444:"metasploit",
  4500:"ipsec-nat",4567:"sinatra",4711:"munin",4848:"glassfish",5000:"flask/upnp",5001:"synology",
  5432:"postgresql",5555:"adb",5601:"kibana",5672:"amqp",5683:"coap",5900:"vnc",5901:"vnc-1",
  5984:"couchdb",5985:"winrm",5986:"winrm-ssl",6000:"x11",6379:"redis",6443:"kubernetes-api",
  6666:"irc-alt",6667:"irc",6697:"irc-ssl",7000:"cassandra",7001:"weblogic",7002:"weblogic-ssl",
  7070:"realserver",7071:"zimbra",7443:"oracleAS",7474:"neo4j",7547:"cwmp",7777:"cbt",
  8000:"http-alt",8001:"http-alt",8008:"http-alt",8009:"ajp",8010:"xmpp",8042:"yarn-nm",
  8080:"http-proxy",8081:"http-proxy",8082:"http-proxy",8083:"http-proxy",8088:"radan-http",
  8090:"opsmessaging",8091:"couchbase",8096:"emby",8123:"polipo/homeassistant",8139:"puppet",
  8140:"puppet",8161:"activemq",8200:"vaultwarden",8222:"nats-monitor",8333:"bitcoin",
  8443:"https-alt",8500:"consul",8600:"consul-dns",8686:"sun-as-jmxrmi",8765:"ultraseek",
  8834:"nessus",8888:"http-alt",8983:"solr",9000:"sonarqube",9001:"tor-orport",
  9042:"cassandra-native",9043:"websphere",9060:"websphere",9080:"glassfish",
  9090:"prometheus/cockpit",9091:"transmission",9092:"kafka",9100:"jetdirect",
  9200:"elasticsearch",9201:"elasticsearch",9300:"elasticsearch-transport",
  9418:"git",9443:"https-alt",9999:"abyss",10000:"webmin",10250:"kubelet",
  10443:"roundcube",11211:"memcached",11434:"ollama",15672:"rabbitmq-mgmt",
  16080:"mac-server",17000:"oracle-tns",18080:"http-alt",19000:"expo",
  20000:"dnp3",25565:"minecraft",27017:"mongodb",27018:"mongodb",27019:"mongodb",
  28017:"mongodb-web",32768:"filenet",33060:"mysqlx",44818:"ethernetip",
  47001:"winrm",49152:"dynamic",50000:"sap",50070:"hdfs-namenode",
  50075:"hdfs-datanode",61616:"activemq",65535:"dynamic-max",
};

export function lookupPort(port) {
  const p = parseInt(port);
  return PORT_SERVICE_MAP[p] || (p >= 49152 ? "dynamic/ephemeral" : "unknown");
}

export function lookupService(name) {
  const results = [];
  const lower = name.toLowerCase();
  for (const [port, svc] of Object.entries(PORT_SERVICE_MAP)) {
    if (svc.toLowerCase().includes(lower)) results.push({ port: parseInt(port), service: svc });
  }
  return results;
}

// ═══════════════════════════════════════════════════════════════
// SECTION 10: CVSS v3.1 CALCULATOR
// ═══════════════════════════════════════════════════════════════

export function calculateCVSS(vector) {
  const metrics = {};
  const parts = vector.replace(/^CVSS:3\.[01]\//i, "").split("/");
  for (const p of parts) {
    const [k, v] = p.split(":");
    metrics[k] = v;
  }

  const AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
  const AC = { L: 0.77, H: 0.44 };
  const PR_U = { N: 0.85, L: 0.62, H: 0.27 };
  const PR_C = { N: 0.85, L: 0.68, H: 0.50 };
  const UI = { N: 0.85, R: 0.62 };
  const CIA = { N: 0, L: 0.22, H: 0.56 };

  const scopeChanged = metrics.S === "C";
  const prTable = scopeChanged ? PR_C : PR_U;

  const av = AV[metrics.AV] ?? 0;
  const ac = AC[metrics.AC] ?? 0;
  const pr = prTable[metrics.PR] ?? 0;
  const ui = UI[metrics.UI] ?? 0;

  const ci = CIA[metrics.C] ?? 0;
  const ii = CIA[metrics.I] ?? 0;
  const ai = CIA[metrics.A] ?? 0;

  const iss = 1 - ((1 - ci) * (1 - ii) * (1 - ai));
  const impact = scopeChanged
    // CVSS v3.1 scope-changed impact (spec §7.1). The v3.0 form
    // 3.25*(ISS-0.02)^15 gives a wrong score on 80/1296 changed vectors
    // (some crossing a severity boundary) while this is labeled v3.1.
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss * 0.9731 - 0.02, 13)
    : 6.42 * iss;

  const exploitability = 8.22 * av * ac * pr * ui;

  let baseScore;
  if (impact <= 0) {
    baseScore = 0;
  } else if (scopeChanged) {
    baseScore = Math.min(1.08 * (impact + exploitability), 10);
  } else {
    baseScore = Math.min(impact + exploitability, 10);
  }
  baseScore = Math.ceil(baseScore * 10) / 10;

  let severity;
  if (baseScore === 0) severity = "None";
  else if (baseScore <= 3.9) severity = "Low";
  else if (baseScore <= 6.9) severity = "Medium";
  else if (baseScore <= 8.9) severity = "High";
  else severity = "Critical";

  return {
    score: baseScore,
    severity,
    impact: Math.round(impact * 100) / 100,
    exploitability: Math.round(exploitability * 100) / 100,
    vector,
    metrics,
    scopeChanged,
  };
}

// ═══════════════════════════════════════════════════════════════
// SECTION 11: VULNERABILITY REPORT GENERATOR
// ═══════════════════════════════════════════════════════════════

export function generateVulnReport(findings) {
  const now = new Date().toISOString();
  const stats = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) stats[f.severity?.toLowerCase()] = (stats[f.severity?.toLowerCase()] || 0) + 1;

  let md = `# Vulnerability Assessment Report\n\n`;
  md += `**Date:** ${now}\n`;
  md += `**Tool:** Darknode Security Scanner\n\n`;
  md += `## Executive Summary\n\n`;
  md += `| Severity | Count |\n|----------|-------|\n`;
  md += `| Critical | ${stats.critical} |\n`;
  md += `| High | ${stats.high} |\n`;
  md += `| Medium | ${stats.medium} |\n`;
  md += `| Low | ${stats.low} |\n`;
  md += `| Info | ${stats.info} |\n`;
  md += `| **Total** | **${findings.length}** |\n\n`;
  md += `## Findings\n\n`;

  for (let i = 0; i < findings.length; i++) {
    const f = findings[i];
    md += `### ${i + 1}. ${f.title}\n\n`;
    md += `- **Severity:** ${f.severity}\n`;
    if (f.cvss) md += `- **CVSS:** ${f.cvss}\n`;
    md += `- **Category:** ${f.category || "General"}\n`;
    if (f.cwe) md += `- **CWE:** ${f.cwe}\n`;
    md += `\n**Description:**\n${f.description}\n\n`;
    if (f.evidence) md += `**Evidence:**\n\`\`\`\n${f.evidence}\n\`\`\`\n\n`;
    if (f.remediation) md += `**Remediation:**\n${f.remediation}\n\n`;
    if (f.references) md += `**References:**\n${f.references.map(r => `- ${r}`).join("\n")}\n\n`;
    md += `---\n\n`;
  }

  md += `## Disclaimer\n\nThis report was generated by Darknode for authorized security testing only. Findings should be verified manually before remediation.\n`;

  return { markdown: md, stats, total: findings.length, date: now };
}

// ═══════════════════════════════════════════════════════════════
// SECTION 12: OWASP TOP 10 CHECKER
// ═══════════════════════════════════════════════════════════════

export const OWASP_TOP_10 = [
  {
    id: "A01:2021",
    name: "Broken Access Control",
    tests: [
      "Test for IDOR (change user IDs in URLs/API calls)",
      "Check for missing authorization on admin endpoints",
      "Verify JWT/session tokens enforce proper access",
      "Test horizontal privilege escalation (access other users' data)",
      "Test vertical privilege escalation (access admin functions as user)",
      "Check CORS configuration for permissive origins",
      "Test forced browsing to restricted pages",
      "Verify access control on API endpoints matches UI restrictions",
    ],
    payloads: ["Change id=1 to id=2", "Remove auth header", "Modify JWT role claim"],
  },
  {
    id: "A02:2021",
    name: "Cryptographic Failures",
    tests: [
      "Check for data transmitted over HTTP (not HTTPS)",
      "Verify HSTS header is present and properly configured",
      "Check for weak TLS versions (TLS 1.0, 1.1)",
      "Verify no sensitive data in URLs/query strings",
      "Check for weak cipher suites",
      "Verify password hashing (bcrypt/argon2 vs MD5/SHA1)",
      "Check for hardcoded secrets in source code",
      "Verify encryption at rest for sensitive data",
    ],
  },
  {
    id: "A03:2021",
    name: "Injection",
    tests: [
      "Test SQL injection in all input fields",
      "Test NoSQL injection (MongoDB operators in JSON)",
      "Test command injection in system-interacting features",
      "Test XSS (reflected, stored, DOM-based)",
      "Test LDAP injection in directory-connected features",
      "Test XML/XXE injection in XML-accepting endpoints",
      "Test SSTI in templating features",
      "Test header injection (CRLF, Host header)",
    ],
  },
  {
    id: "A04:2021",
    name: "Insecure Design",
    tests: [
      "Review business logic for flaws (negative quantities, race conditions)",
      "Check rate limiting on sensitive endpoints",
      "Verify MFA is available and enforced",
      "Test for enumeration (user, email, password reset)",
      "Check for insecure direct object references in design",
      "Review for trust boundary violations",
    ],
  },
  {
    id: "A05:2021",
    name: "Security Misconfiguration",
    tests: [
      "Check for default credentials on all services",
      "Verify unnecessary features are disabled",
      "Check security headers (CSP, X-Frame-Options, etc.)",
      "Test for verbose error messages exposing internals",
      "Check for exposed admin panels/debug endpoints",
      "Verify directory listing is disabled",
      "Check for outdated software versions",
      "Test for open cloud storage (S3, GCS, Azure Blobs)",
    ],
  },
  {
    id: "A06:2021",
    name: "Vulnerable and Outdated Components",
    tests: [
      "Check JavaScript library versions (jQuery, Bootstrap, etc.)",
      "Scan for known CVEs in detected components",
      "Check server software versions",
      "Verify CMS and plugin versions",
      "Review dependency tree for vulnerabilities",
    ],
  },
  {
    id: "A07:2021",
    name: "Identification and Authentication Failures",
    tests: [
      "Test for brute force protection (account lockout, rate limiting)",
      "Check password policy (length, complexity, common passwords)",
      "Test for credential stuffing resistance",
      "Verify session management (timeout, rotation, fixation)",
      "Check for MFA bypass techniques",
      "Test for default/weak credentials",
      "Verify password reset flow security",
    ],
  },
  {
    id: "A08:2021",
    name: "Software and Data Integrity Failures",
    tests: [
      "Check for insecure deserialization",
      "Verify CI/CD pipeline security",
      "Check for unsigned/unverified updates",
      "Test for prototype pollution (JavaScript)",
      "Verify subresource integrity (SRI) on CDN resources",
    ],
  },
  {
    id: "A09:2021",
    name: "Security Logging and Monitoring Failures",
    tests: [
      "Verify login attempts are logged",
      "Check for log injection vulnerabilities",
      "Verify alerting on suspicious activity",
      "Check for adequate log retention",
      "Test if security events trigger notifications",
    ],
  },
  {
    id: "A10:2021",
    name: "Server-Side Request Forgery (SSRF)",
    tests: [
      "Test URL input fields for SSRF (internal network access)",
      "Check for cloud metadata access (169.254.169.254)",
      "Test file:// and other protocol handlers",
      "Verify URL validation and allowlisting",
      "Test for DNS rebinding attacks",
    ],
  },
];

// ═══════════════════════════════════════════════════════════════
// SECTION 13: SSL/TLS CIPHER SUITE RATING
// ═══════════════════════════════════════════════════════════════

export function rateCipherSuite(cipher) {
  const c = cipher.toUpperCase();
  const issues = [];
  let score = 100;

  if (c.includes("NULL") || c.includes("ANON")) { issues.push("NULL/anonymous cipher"); score = 0; }
  if (c.includes("EXPORT")) { issues.push("Export-grade cipher"); score = Math.min(score, 10); }
  if (c.includes("DES") && !c.includes("3DES")) { issues.push("Single DES (56-bit)"); score = Math.min(score, 20); }
  if (c.includes("3DES")) { issues.push("Triple DES (deprecated)"); score = Math.min(score, 50); }
  if (c.includes("RC4")) { issues.push("RC4 (broken)"); score = Math.min(score, 30); }
  if (c.includes("MD5")) { issues.push("MD5 MAC (weak)"); score = Math.min(score, 40); }
  if (c.includes("SHA1") || (c.includes("SHA") && !c.includes("SHA256") && !c.includes("SHA384"))) {
    issues.push("SHA-1 (deprecated)"); score = Math.min(score, 60);
  }
  if (c.includes("RSA") && !c.includes("ECDHE") && !c.includes("DHE")) {
    issues.push("No forward secrecy (static RSA)"); score = Math.min(score, 70);
  }
  if (c.includes("CBC")) { issues.push("CBC mode (BEAST/Lucky13 vulnerable)"); score = Math.min(score, 80); }

  if (c.includes("CHACHA20")) score = Math.min(score + 5, 100);
  if (c.includes("GCM")) score = Math.min(score + 5, 100);
  if (c.includes("ECDHE")) score = Math.min(score + 5, 100);

  let grade;
  if (score >= 90) grade = "A";
  else if (score >= 70) grade = "B";
  else if (score >= 50) grade = "C";
  else if (score >= 30) grade = "D";
  else grade = "F";

  return { cipher, score, grade, issues, secure: score >= 70 };
}

export function rateTLSConfig(protocol, ciphers) {
  const protocolScores = {
    "TLSv1.3": 100, "TLSv1.2": 85, "TLSv1.1": 40, "TLSv1.0": 20,
    "SSLv3": 0, "SSLv2": 0
  };
  const protoScore = protocolScores[protocol] || 0;
  const cipherResults = ciphers.map(rateCipherSuite);
  const avgCipherScore = cipherResults.length > 0
    ? cipherResults.reduce((s, r) => s + r.score, 0) / cipherResults.length
    : 0;
  const weakCiphers = cipherResults.filter(r => r.score < 50);
  const overall = Math.round((protoScore * 0.4 + avgCipherScore * 0.6));

  let grade;
  if (overall >= 90) grade = "A";
  else if (overall >= 70) grade = "B";
  else if (overall >= 50) grade = "C";
  else if (overall >= 30) grade = "D";
  else grade = "F";

  return { grade, score: overall, protocol, protocolScore: protoScore, cipherResults, weakCiphers, totalCiphers: ciphers.length };
}

// ═══════════════════════════════════════════════════════════════
// SECTION 14: GRAPHQL INTROSPECTION ANALYZER
// ═══════════════════════════════════════════════════════════════

export function analyzeGraphQLSchema(introspectionResult) {
  const schema = introspectionResult?.data?.__schema || introspectionResult?.__schema;
  if (!schema) return { error: "Invalid introspection result" };

  const types = schema.types || [];
  const queries = [];
  const mutations = [];
  const sensitiveFields = [];
  const sensitivePatterns = /password|secret|token|key|auth|credential|ssn|credit|card|cvv|pin|private|internal|admin|debug|hash|salt|session/i;

  const queryType = types.find(t => t.name === schema.queryType?.name);
  const mutationType = types.find(t => t.name === schema.mutationType?.name);

  if (queryType?.fields) {
    for (const f of queryType.fields) {
      queries.push({ name: f.name, type: formatGraphQLType(f.type), args: (f.args || []).map(a => a.name) });
      if (sensitivePatterns.test(f.name)) sensitiveFields.push({ field: f.name, location: "Query", risk: "high" });
    }
  }

  if (mutationType?.fields) {
    for (const f of mutationType.fields) {
      mutations.push({ name: f.name, type: formatGraphQLType(f.type), args: (f.args || []).map(a => a.name) });
      if (sensitivePatterns.test(f.name)) sensitiveFields.push({ field: f.name, location: "Mutation", risk: "high" });
    }
  }

  for (const t of types) {
    if (t.name.startsWith("__") || !t.fields) continue;
    for (const f of t.fields) {
      if (sensitivePatterns.test(f.name)) {
        sensitiveFields.push({ field: `${t.name}.${f.name}`, location: "Type", risk: "medium" });
      }
    }
  }

  const userTypes = types.filter(t => !t.name.startsWith("__") && t.kind === "OBJECT");

  return {
    queries: queries.length,
    mutations: mutations.length,
    types: userTypes.length,
    sensitiveFields,
    queryList: queries,
    mutationList: mutations,
    typeList: userTypes.map(t => ({ name: t.name, fields: (t.fields || []).length })),
    introspectionEnabled: true,
    risks: [
      "Introspection is enabled — exposes full API schema",
      ...sensitiveFields.map(f => `Sensitive field: ${f.field}`),
      mutations.length > 0 ? `${mutations.length} mutations exposed` : null,
    ].filter(Boolean),
  };
}

function formatGraphQLType(type) {
  if (!type) return "Unknown";
  if (type.kind === "NON_NULL") return formatGraphQLType(type.ofType) + "!";
  if (type.kind === "LIST") return "[" + formatGraphQLType(type.ofType) + "]";
  return type.name || "Unknown";
}

export const GRAPHQL_INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name kind description
      fields(includeDeprecated: true) {
        name
        type { name kind ofType { name kind ofType { name kind } } }
        args { name type { name kind } }
      }
    }
  }
}`;

// ═══════════════════════════════════════════════════════════════
// SECTION 15: API SECURITY TESTER
// ═══════════════════════════════════════════════════════════════

export function generateAPITests(baseUrl, endpoints = []) {
  const tests = [];

  for (const ep of endpoints) {
    const url = baseUrl + ep.path;

    tests.push({
      name: `BOLA: ${ep.path}`,
      category: "Broken Object-Level Authorization",
      request: { method: ep.method || "GET", url: url.replace(/\/\d+/, "/9999"), headers: {} },
      check: "Response should be 403/404, not 200 with another user's data",
    });

    if (ep.method === "GET") {
      tests.push({
        name: `Excessive Data: ${ep.path}`,
        category: "Excessive Data Exposure",
        request: { method: "GET", url, headers: {} },
        check: "Response should not contain sensitive fields (password, SSN, tokens, internal IDs)",
      });
    }

    tests.push({
      name: `No Auth: ${ep.path}`,
      category: "Broken Authentication",
      request: { method: ep.method || "GET", url, headers: {} },
      check: "Response without auth should be 401/403, not 200",
    });

    if (ep.method === "POST" || ep.method === "PUT") {
      tests.push({
        name: `Mass Assignment: ${ep.path}`,
        category: "Mass Assignment",
        request: { method: ep.method, url, body: { role: "admin", is_admin: true, verified: true }, headers: { "Content-Type": "application/json" } },
        check: "Server should ignore unexpected fields (role, is_admin, etc.)",
      });
    }

    tests.push({
      name: `Rate Limit: ${ep.path}`,
      category: "Lack of Resources & Rate Limiting",
      request: { method: ep.method || "GET", url, headers: {} },
      check: "After 100+ rapid requests, server should return 429 Too Many Requests",
    });

    if (ep.method === "GET" && ep.path.includes("?")) {
      tests.push({
        name: `Injection: ${ep.path}`,
        category: "Injection",
        request: { method: "GET", url: url + "' OR 1=1--", headers: {} },
        check: "Response should be 400 or filtered, not a SQL error or data dump",
      });
    }
  }

  return tests;
}

export function generateSecurityScanReport(target, headers, html) {
  const fingerprint = fingerprintServer(headers);
  const cms = detectCMS(html, headers);
  const tech = detectTechStack(html, headers);
  const secHeaders = analyzeSecurityHeaders(headers);

  return {
    target,
    timestamp: new Date().toISOString(),
    server: fingerprint,
    cms,
    technology: tech,
    securityHeaders: secHeaders,
    summary: {
      headerGrade: secHeaders.grade,
      headersPresent: `${secHeaders.present}/${secHeaders.total}`,
      serverDisclosed: !!fingerprint.server,
      cmsDetected: cms.length > 0 ? cms[0].cms : "None",
      wafDetected: tech.waf.length > 0 ? tech.waf.join(", ") : "None",
      infoLeaks: secHeaders.leaks.length,
    }
  };
}
