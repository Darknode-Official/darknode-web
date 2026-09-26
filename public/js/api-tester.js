// API Tester — HTTP API security testing tool (client-side fetch)
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
const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"];
const CONTENT_TYPES = [
  { label: "None", value: "" },
  { label: "JSON", value: "application/json" },
  { label: "Form URL-encoded", value: "application/x-www-form-urlencoded" },
  { label: "Plain Text", value: "text/plain" },
  { label: "XML", value: "application/xml" },
];

const STATUS_MEANINGS = {
  200: "OK", 201: "Created", 202: "Accepted", 204: "No Content",
  301: "Moved Permanently", 302: "Found", 304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect",
  400: "Bad Request", 401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed",
  406: "Not Acceptable", 408: "Request Timeout", 409: "Conflict", 410: "Gone", 413: "Payload Too Large",
  415: "Unsupported Media Type", 422: "Unprocessable Entity", 429: "Too Many Requests",
  500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway", 503: "Service Unavailable", 504: "Gateway Timeout",
};

const SECURITY_HEADERS = [
  { name: "Content-Security-Policy", importance: "critical", desc: "Controls which resources the browser loads. Prevents XSS, clickjacking, and data injection." },
  { name: "Strict-Transport-Security", importance: "critical", desc: "Forces HTTPS for all future requests. Prevents SSL stripping attacks." },
  { name: "X-Frame-Options", importance: "high", desc: "Prevents clickjacking by controlling iframe embedding. Use DENY or SAMEORIGIN." },
  { name: "X-Content-Type-Options", importance: "high", desc: "Prevents MIME-type sniffing. Should be set to nosniff." },
  { name: "Referrer-Policy", importance: "medium", desc: "Controls how much referrer info is sent with requests." },
  { name: "Permissions-Policy", importance: "medium", desc: "Controls which browser features and APIs the page can use." },
  { name: "X-XSS-Protection", importance: "low", desc: "Legacy XSS filter. Most browsers ignore it now; CSP is the modern replacement." },
  { name: "Cross-Origin-Opener-Policy", importance: "medium", desc: "Isolates the browsing context group. Prevents Spectre-type side-channel attacks." },
  { name: "Cross-Origin-Resource-Policy", importance: "medium", desc: "Controls which origins can load the resource." },
  { name: "Cross-Origin-Embedder-Policy", importance: "medium", desc: "Controls whether the document can load cross-origin resources." },
  { name: "Cache-Control", importance: "medium", desc: "Controls caching. Sensitive responses should use no-store." },
  { name: "X-Permitted-Cross-Domain-Policies", importance: "low", desc: "Controls Adobe Flash/PDF cross-domain policies." },
];

const REQUEST_TEMPLATES = {
  "REST - List": { method: "GET", url: "{{base_url}}/api/items", headers: [{ key: "Accept", value: "application/json" }], body: "" },
  "REST - Create": { method: "POST", url: "{{base_url}}/api/items", headers: [{ key: "Content-Type", value: "application/json" }], body: '{\n  "name": "test",\n  "value": 123\n}' },
  "REST - Update": { method: "PUT", url: "{{base_url}}/api/items/1", headers: [{ key: "Content-Type", value: "application/json" }], body: '{\n  "name": "updated",\n  "value": 456\n}' },
  "REST - Delete": { method: "DELETE", url: "{{base_url}}/api/items/1", headers: [], body: "" },
  "GraphQL - Query": { method: "POST", url: "{{base_url}}/graphql", headers: [{ key: "Content-Type", value: "application/json" }], body: '{\n  "query": "{ users { id name email } }"\n}' },
  "GraphQL - Mutation": { method: "POST", url: "{{base_url}}/graphql", headers: [{ key: "Content-Type", value: "application/json" }], body: '{\n  "query": "mutation { createUser(name: \\"test\\") { id } }"\n}' },
  "OAuth2 - Token": { method: "POST", url: "{{base_url}}/oauth/token", headers: [{ key: "Content-Type", value: "application/x-www-form-urlencoded" }], body: "grant_type=client_credentials&client_id={{client_id}}&client_secret={{client_secret}}" },
  "Health Check": { method: "GET", url: "{{base_url}}/health", headers: [], body: "" },
};

function decodeJWT(token) {
  try {
    var parts = token.split(".");
    if (parts.length !== 3) return null;
    var header = _jwtSegJson(parts[0]);
    var payload = _jwtSegJson(parts[1]);
    var issues = [];
    if (header.alg === "none") issues.push("CRITICAL: Algorithm is 'none' - token is unsigned");
    if (header.alg === "HS256" && header.jku) issues.push("WARNING: jku header present with symmetric algorithm");
    if (payload.exp && payload.exp * 1000 < Date.now()) issues.push("Token is expired");
    if (!payload.exp) issues.push("No expiration claim (exp) - token never expires");
    if (!payload.iss) issues.push("No issuer claim (iss)");
    if (!payload.aud) issues.push("No audience claim (aud)");
    return { header: header, payload: payload, signature: parts[2], issues: issues };
  } catch (_) { return null; }
}

function parseCookies(setCookieHeaders) {
  var cookies = [];
  setCookieHeaders.forEach(function(h) {
    var parts = h.split(";").map(function(p) { return p.trim(); });
    var nameVal = parts[0].split("=");
    var cookie = { name: nameVal[0], value: nameVal.slice(1).join("="), flags: [], issues: [] };
    var hasSecure = false, hasHttpOnly = false, hasSameSite = false;
    for (var i = 1; i < parts.length; i++) {
      var p = parts[i].toLowerCase();
      cookie.flags.push(parts[i]);
      if (p === "secure") hasSecure = true;
      if (p === "httponly") hasHttpOnly = true;
      if (p.indexOf("samesite") === 0) hasSameSite = true;
    }
    if (!hasSecure) cookie.issues.push("Missing Secure flag - cookie sent over HTTP");
    if (!hasHttpOnly) cookie.issues.push("Missing HttpOnly flag - accessible via JavaScript (XSS risk)");
    if (!hasSameSite) cookie.issues.push("Missing SameSite attribute - vulnerable to CSRF");
    cookies.push(cookie);
  });
  return cookies;
}

function toCurl(method, url, headers, body) {
  var cmd = "curl -X " + method;
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].key) cmd += " \\\n  -H '" + headers[i].key + ": " + headers[i].value + "'";
  }
  if (body && method !== "GET" && method !== "HEAD") {
    cmd += " \\\n  -d '" + body.replace(/'/g, "'\\''") + "'";
  }
  cmd += " \\\n  '" + url + "'";
  return cmd;
}

function parseCurl(text) {
  var result = { method: "GET", url: "", headers: [], body: "" };
  text = text.replace(/\\\n/g, " ").trim();
  if (text.indexOf("curl ") !== 0) return null;
  var tokens = [];
  var inQuote = false, quoteChar = "", current = "";
  for (var i = 5; i < text.length; i++) {
    var c = text[i];
    if (inQuote) {
      if (c === quoteChar) { inQuote = false; tokens.push(current); current = ""; }
      else current += c;
    } else {
      if (c === "'" || c === '"') { inQuote = true; quoteChar = c; }
      else if (c === " " || c === "\t") { if (current) { tokens.push(current); current = ""; } }
      else current += c;
    }
  }
  if (current) tokens.push(current);

  for (var j = 0; j < tokens.length; j++) {
    var t = tokens[j];
    if (t === "-X" || t === "--request") { result.method = (tokens[++j] || "GET").toUpperCase(); }
    else if (t === "-H" || t === "--header") {
      var hdr = tokens[++j] || "";
      var idx = hdr.indexOf(":");
      if (idx > 0) result.headers.push({ key: hdr.substring(0, idx).trim(), value: hdr.substring(idx + 1).trim() });
    }
    else if (t === "-d" || t === "--data" || t === "--data-raw") { result.body = tokens[++j] || ""; }
    else if (t.indexOf("http") === 0) { result.url = t; }
  }
  return result;
}

function substituteEnvVars(text, envVars) {
  for (var key in envVars) {
    text = text.replace(new RegExp("\\{\\{" + key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "\\}\\}", "g"), envVars[key]);
  }
  return text;
}

function formatBody(body, contentType) {
  if (!body) return "";
  if (contentType && contentType.indexOf("json") !== -1) {
    try { return JSON.stringify(JSON.parse(body), null, 2); } catch (_) { return body; }
  }
  if (contentType && contentType.indexOf("xml") !== -1) {
    return body;
  }
  return body;
}

export function renderAPITester(main) {
  var history = [];
  try { history = JSON.parse(localStorage.getItem("api_history") || "[]"); } catch (_) {}
  var envVars = {};
  try { envVars = JSON.parse(localStorage.getItem("api_env") || "{}"); } catch (_) {}
  var collections = [];
  try { collections = JSON.parse(localStorage.getItem("api_collections") || "[]"); } catch (_) {}

  function saveHistory() { try { localStorage.setItem("api_history", JSON.stringify(history.slice(0, 50))); } catch (_) {} }
  function saveEnv() { try { localStorage.setItem("api_env", JSON.stringify(envVars)); } catch (_) {} }
  function saveCollections() { try { localStorage.setItem("api_collections", JSON.stringify(collections)); } catch (_) {} }

  main.innerHTML =
    '<h1 class="pg-h1">API Tester</h1>' +
    '<p class="muted pg-sub">HTTP API security testing tool. All requests are made client-side via fetch.</p>' +

    '<div class="tab-bar" id="at-tabs">' +
      '<button class="tab active" data-tab="request">Request Builder</button>' +
      '<button class="tab" data-tab="security">Security Check</button>' +
      '<button class="tab" data-tab="history">History</button>' +
      '<button class="tab" data-tab="templates">Templates</button>' +
      '<button class="tab" data-tab="curl">cURL Import</button>' +
      '<button class="tab" data-tab="env">Environment</button>' +
      '<button class="tab" data-tab="collections">Collections</button>' +
    '</div>' +
    '<div id="at-content"></div>';

  var tabBar = main.querySelector("#at-tabs");
  var content = main.querySelector("#at-content");

  function renderTab(tabId) {
    tabBar.querySelectorAll(".tab").forEach(function(t) { t.classList.toggle("active", t.dataset.tab === tabId); });

    if (tabId === "request") {
      var methodOpts = METHODS.map(function(m) { return '<option value="' + m + '">' + m + '</option>'; }).join("");
      content.innerHTML =
        '<div style="display:flex;gap:8px;margin-bottom:12px">' +
          '<select class="tk-f" id="at-method" style="max-width:120px">' + methodOpts + '</select>' +
          '<input class="tk-f" id="at-url" placeholder="https://api.example.com/endpoint" style="flex:1">' +
          '<button class="btn sm" id="at-send">Send</button>' +
        '</div>' +
        '<div style="margin-bottom:12px">' +
          '<div style="display:flex;justify-content:space-between;align-items:center">' +
            '<label style="font-size:.82rem;font-weight:500">Headers</label>' +
            '<button class="btn sm ghost" id="at-add-header" style="padding:2px 8px;font-size:.72rem">+ Add</button>' +
          '</div>' +
          '<div id="at-headers" style="margin-top:4px"></div>' +
        '</div>' +
        '<div style="margin-bottom:12px">' +
          '<div style="display:flex;align-items:center;gap:12px;margin-bottom:4px">' +
            '<label style="font-size:.82rem;font-weight:500">Auth</label>' +
            '<select class="tk-f" id="at-auth-type" style="max-width:180px">' +
              '<option value="none">None</option>' +
              '<option value="bearer">Bearer Token</option>' +
              '<option value="basic">Basic Auth</option>' +
              '<option value="apikey-header">API Key (Header)</option>' +
              '<option value="apikey-query">API Key (Query Param)</option>' +
            '</select>' +
          '</div>' +
          '<div id="at-auth-fields"></div>' +
        '</div>' +
        '<div style="margin-bottom:12px">' +
          '<label style="font-size:.82rem;font-weight:500">Body</label>' +
          '<textarea class="tk-in" id="at-body" rows="6" placeholder="Request body (JSON, form data, etc.)"></textarea>' +
        '</div>' +
        '<div id="at-response" style="margin-top:16px"></div>';

      var headerContainer = content.querySelector("#at-headers");
      var headerList = [{ key: "", value: "" }];

      function renderHeaders() {
        headerContainer.innerHTML = headerList.map(function(h, i) {
          return '<div style="display:flex;gap:6px;margin-bottom:4px">' +
            '<input class="tk-f at-hk" data-idx="' + i + '" placeholder="Header name" value="' + esc(h.key) + '" style="flex:1">' +
            '<input class="tk-f at-hv" data-idx="' + i + '" placeholder="Value" value="' + esc(h.value) + '" style="flex:2">' +
            '<button class="btn sm danger at-hdel" data-idx="' + i + '" style="padding:2px 6px">X</button>' +
          '</div>';
        }).join("");
        headerContainer.querySelectorAll(".at-hk").forEach(function(inp) { inp.oninput = function() { headerList[parseInt(inp.dataset.idx)].key = inp.value; }; });
        headerContainer.querySelectorAll(".at-hv").forEach(function(inp) { inp.oninput = function() { headerList[parseInt(inp.dataset.idx)].value = inp.value; }; });
        headerContainer.querySelectorAll(".at-hdel").forEach(function(btn) {
          btn.onclick = function() { headerList.splice(parseInt(btn.dataset.idx), 1); if (!headerList.length) headerList.push({ key: "", value: "" }); renderHeaders(); };
        });
      }
      renderHeaders();

      content.querySelector("#at-add-header").onclick = function() { headerList.push({ key: "", value: "" }); renderHeaders(); };

      var authFields = content.querySelector("#at-auth-fields");
      var authType = content.querySelector("#at-auth-type");
      function renderAuthFields() {
        var type = authType.value;
        if (type === "none") { authFields.innerHTML = ""; return; }
        if (type === "bearer") {
          authFields.innerHTML = '<input class="tk-f" id="at-auth-token" placeholder="Bearer token" style="margin-top:4px">';
        } else if (type === "basic") {
          authFields.innerHTML = '<div style="display:flex;gap:6px;margin-top:4px"><input class="tk-f" id="at-auth-user" placeholder="Username"><input class="tk-f" id="at-auth-pass" placeholder="Password" type="password"></div>';
        } else if (type === "apikey-header" || type === "apikey-query") {
          authFields.innerHTML = '<div style="display:flex;gap:6px;margin-top:4px"><input class="tk-f" id="at-auth-key-name" placeholder="Key name (e.g. X-API-Key)" value="X-API-Key"><input class="tk-f" id="at-auth-key-val" placeholder="Key value"></div>';
        }
      }
      authType.onchange = renderAuthFields;

      content.querySelector("#at-send").onclick = async function() {
        var method = content.querySelector("#at-method").value;
        var rawUrl = content.querySelector("#at-url").value.trim();
        var body = content.querySelector("#at-body").value;
        var url = substituteEnvVars(rawUrl, envVars);
        body = substituteEnvVars(body, envVars);
        if (!url) { content.querySelector("#at-response").innerHTML = '<div style="color:#ef4444">Enter a URL.</div>'; return; }

        var fetchHeaders = {};
        headerList.forEach(function(h) { if (h.key) fetchHeaders[h.key] = substituteEnvVars(h.value, envVars); });

        var aType = authType.value;
        if (aType === "bearer") {
          var token = (content.querySelector("#at-auth-token") || {}).value || "";
          if (token) fetchHeaders["Authorization"] = "Bearer " + substituteEnvVars(token, envVars);
        } else if (aType === "basic") {
          var user = (content.querySelector("#at-auth-user") || {}).value || "";
          var pass = (content.querySelector("#at-auth-pass") || {}).value || "";
          if (user) fetchHeaders["Authorization"] = "Basic " + btoa(user + ":" + pass);
        } else if (aType === "apikey-header") {
          var kn = (content.querySelector("#at-auth-key-name") || {}).value || "X-API-Key";
          var kv = (content.querySelector("#at-auth-key-val") || {}).value || "";
          if (kv) fetchHeaders[kn] = substituteEnvVars(kv, envVars);
        } else if (aType === "apikey-query") {
          var qn = (content.querySelector("#at-auth-key-name") || {}).value || "api_key";
          var qv = (content.querySelector("#at-auth-key-val") || {}).value || "";
          if (qv) url += (url.indexOf("?") === -1 ? "?" : "&") + encodeURIComponent(qn) + "=" + encodeURIComponent(substituteEnvVars(qv, envVars));
        }

        content.querySelector("#at-response").innerHTML = '<div style="color:var(--mut)">Sending...</div>';
        var startTime = performance.now();
        try {
          var fetchOpts = { method: method, headers: fetchHeaders, mode: "cors" };
          if (body && method !== "GET" && method !== "HEAD") fetchOpts.body = body;
          var resp = await fetch(url, fetchOpts);
          var elapsed = Math.round(performance.now() - startTime);
          var respBody = "";
          try { respBody = await resp.text(); } catch (_) {}
          var ct = resp.headers.get("content-type") || "";
          var formatted = formatBody(respBody, ct);
          var statusColor = resp.status < 300 ? "#22c55e" : (resp.status < 400 ? "#3b82f6" : (resp.status < 500 ? "#f59e0b" : "#ef4444"));
          var statusText = STATUS_MEANINGS[resp.status] || "";

          var respHeaders = [];
          resp.headers.forEach(function(v, k) { respHeaders.push({ key: k, value: v }); });

          var setCookies = [];
          resp.headers.forEach(function(v, k) { if (k.toLowerCase() === "set-cookie") setCookies.push(v); });

          var jwtInBody = null;
          var jwtMatch = respBody.match(/"(?:token|access_token|id_token|jwt)":\s*"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)"/);
          if (jwtMatch) jwtInBody = decodeJWT(jwtMatch[1]);

          var entry = { method: method, url: rawUrl, status: resp.status, elapsed: elapsed, time: new Date().toISOString() };
          history.unshift(entry);
          saveHistory();

          var html =
            '<div style="border:1px solid var(--line);border-radius:6px;overflow:hidden;margin-top:12px">' +
              '<div style="padding:10px 14px;background:var(--card2);display:flex;align-items:center;gap:12px;border-bottom:1px solid var(--line)">' +
                '<span style="font-weight:700;font-size:1.1rem;color:' + statusColor + '">' + resp.status + '</span>' +
                '<span style="color:var(--mut);font-size:.85rem">' + esc(statusText) + '</span>' +
                '<span style="margin-left:auto;font-size:.78rem;color:var(--mut)">' + elapsed + 'ms</span>' +
                '<span style="font-size:.78rem;color:var(--mut)">' + (respBody.length / 1024).toFixed(1) + ' KB</span>' +
              '</div>' +
              '<div style="padding:10px 14px">' +
                '<div style="margin-bottom:8px"><strong style="font-size:.82rem">Response Headers</strong></div>' +
                '<div style="max-height:200px;overflow:auto">' +
                  respHeaders.map(function(h) {
                    return '<div style="font-size:.78rem;padding:2px 0;font-family:var(--mono,monospace)"><span style="color:var(--acc)">' + esc(h.key) + ':</span> ' + esc(h.value) + '</div>';
                  }).join("") +
                '</div>' +
              '</div>' +
              '<div style="padding:10px 14px;border-top:1px solid var(--line)">' +
                '<div style="margin-bottom:8px"><strong style="font-size:.82rem">Response Body</strong></div>' +
                '<pre class="tk-out" style="max-height:400px;overflow:auto">' + esc(formatted) + '</pre>' +
              '</div>' +
            '</div>';

          if (jwtInBody) {
            html += '<div style="border:1px solid var(--line);border-radius:6px;padding:12px;margin-top:8px">' +
              '<strong style="font-size:.82rem">JWT Detected in Response</strong>' +
              '<div style="margin-top:6px;font-size:.78rem">' +
                '<div><span style="color:var(--acc)">Algorithm:</span> ' + esc(jwtInBody.header.alg) + '</div>' +
                '<div><span style="color:var(--acc)">Payload:</span></div>' +
                '<pre class="tk-out" style="max-height:150px">' + esc(JSON.stringify(jwtInBody.payload, null, 2)) + '</pre>' +
                (jwtInBody.issues.length ? '<div style="margin-top:6px">' + jwtInBody.issues.map(function(iss) {
                  return '<div style="color:#f59e0b;font-size:.78rem">[!] ' + esc(iss) + '</div>';
                }).join("") + '</div>' : '') +
              '</div>' +
            '</div>';
          }

          content.querySelector("#at-response").innerHTML = html;
        } catch (err) {
          var elapsed2 = Math.round(performance.now() - startTime);
          content.querySelector("#at-response").innerHTML =
            '<div style="border:1px solid #ef4444;border-radius:6px;padding:14px;margin-top:12px">' +
              '<div style="color:#ef4444;font-weight:600">Request Failed</div>' +
              '<div style="font-size:.82rem;color:var(--mut);margin-top:4px">' + esc(err.message) + '</div>' +
              '<div style="font-size:.78rem;color:var(--mut);margin-top:4px">Time: ' + elapsed2 + 'ms</div>' +
              '<div style="font-size:.78rem;color:var(--mut);margin-top:8px">Common causes: CORS policy blocking the request, network error, invalid URL, or the server is down.</div>' +
            '</div>';
        }
      };

    } else if (tabId === "security") {
      content.innerHTML =
        '<h2 class="pg-h2">Security Header Check</h2>' +
        '<p class="muted" style="font-size:.82rem">Enter a URL to check its security headers.</p>' +
        '<div style="display:flex;gap:8px;margin:12px 0">' +
          '<input class="tk-f" id="at-sec-url" placeholder="https://example.com">' +
          '<button class="btn sm" id="at-sec-check">Check</button>' +
        '</div>' +
        '<div id="at-sec-result"></div>' +
        '<div style="margin-top:20px">' +
          '<h3 style="font-size:.9rem;margin-bottom:8px">Security Header Reference</h3>' +
          '<div style="display:grid;gap:6px">' +
            SECURITY_HEADERS.map(function(h) {
              var color = h.importance === "critical" ? "#ef4444" : (h.importance === "high" ? "#f59e0b" : (h.importance === "medium" ? "#3b82f6" : "var(--mut)"));
              return '<div style="padding:8px 12px;border-left:3px solid ' + color + ';background:var(--card2);border-radius:0 4px 4px 0;font-size:.8rem">' +
                '<div style="font-weight:600;font-family:var(--mono,monospace)">' + esc(h.name) + ' <span style="font-size:.7rem;color:' + color + ';font-weight:400">' + h.importance.toUpperCase() + '</span></div>' +
                '<div style="color:var(--mut);margin-top:2px">' + esc(h.desc) + '</div>' +
              '</div>';
            }).join("") +
          '</div>' +
        '</div>';

      content.querySelector("#at-sec-check").onclick = async function() {
        var url = substituteEnvVars(content.querySelector("#at-sec-url").value.trim(), envVars);
        if (!url) return;
        var out = content.querySelector("#at-sec-result");
        out.innerHTML = '<div style="color:var(--mut)">Checking...</div>';
        try {
          var resp = await fetch(url, { method: "HEAD", mode: "cors" });
          var results = SECURITY_HEADERS.map(function(h) {
            var val = resp.headers.get(h.name);
            return { name: h.name, present: !!val, value: val || "Not set", importance: h.importance };
          });
          var score = results.filter(function(r) { return r.present; }).length;
          var total = results.length;
          var pct = Math.round(score / total * 100);
          var scoreColor = pct >= 80 ? "#22c55e" : (pct >= 50 ? "#f59e0b" : "#ef4444");

          out.innerHTML =
            '<div style="text-align:center;margin:12px 0"><span style="font-size:2rem;font-weight:700;color:' + scoreColor + '">' + pct + '%</span><div style="font-size:.82rem;color:var(--mut)">' + score + '/' + total + ' headers present</div></div>' +
            results.map(function(r) {
              var icon = r.present ? '<span style="color:#22c55e;font-weight:700">[OK]</span>' : '<span style="color:#ef4444;font-weight:700">[MISSING]</span>';
              return '<div style="padding:6px 10px;border-bottom:1px solid var(--line);font-size:.8rem;display:flex;align-items:center;gap:8px">' +
                icon + ' <span style="font-family:var(--mono,monospace);font-weight:500">' + esc(r.name) + '</span>' +
                '<span style="margin-left:auto;color:var(--mut);font-size:.72rem;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(r.value) + '</span></div>';
            }).join("");
        } catch (err) {
          out.innerHTML = '<div style="color:#ef4444">Failed: ' + esc(err.message) + '</div>';
        }
      };

    } else if (tabId === "history") {
      content.innerHTML =
        '<h2 class="pg-h2">Request History</h2>' +
        '<p class="muted" style="font-size:.82rem">' + history.length + ' saved requests. Click to reload.</p>' +
        (history.length ? '<button class="btn sm danger" id="at-clear-hist" style="margin-bottom:8px">Clear History</button>' : '') +
        '<div style="display:grid;gap:4px">' +
          history.map(function(h, i) {
            var methodColor = h.method === "GET" ? "#22c55e" : (h.method === "POST" ? "#3b82f6" : (h.method === "DELETE" ? "#ef4444" : "#f59e0b"));
            var statusColor = h.status < 300 ? "#22c55e" : (h.status < 400 ? "#3b82f6" : (h.status < 500 ? "#f59e0b" : "#ef4444"));
            return '<div class="at-hist-item" data-idx="' + i + '" style="padding:8px 12px;border:1px solid var(--line);border-radius:4px;cursor:pointer;font-size:.8rem;display:flex;align-items:center;gap:10px">' +
              '<span style="font-weight:700;color:' + methodColor + ';min-width:50px">' + esc(h.method) + '</span>' +
              '<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-family:var(--mono,monospace);font-size:.72rem">' + esc(h.url) + '</span>' +
              '<span style="font-weight:600;color:' + statusColor + '">' + (h.status || "--") + '</span>' +
              '<span style="color:var(--mut);font-size:.72rem">' + (h.elapsed || 0) + 'ms</span>' +
              '<span style="color:var(--mut);font-size:.68rem">' + esc(h.time ? h.time.substring(0, 16).replace("T", " ") : "") + '</span>' +
            '</div>';
          }).join("") +
        '</div>';

      var clearHist = content.querySelector("#at-clear-hist");
      if (clearHist) clearHist.onclick = function() { history = []; saveHistory(); renderTab("history"); };

      content.querySelectorAll(".at-hist-item").forEach(function(el) {
        el.onclick = function() {
          var h = history[parseInt(el.dataset.idx)];
          if (h) {
            renderTab("request");
            var urlInput = content.querySelector("#at-url");
            var methodSel = content.querySelector("#at-method");
            if (urlInput) urlInput.value = h.url;
            if (methodSel) methodSel.value = h.method;
          }
        };
      });

    } else if (tabId === "templates") {
      content.innerHTML =
        '<h2 class="pg-h2">Request Templates</h2>' +
        '<p class="muted" style="font-size:.82rem">Click a template to load it into the request builder.</p>' +
        '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;margin-top:12px">' +
          Object.keys(REQUEST_TEMPLATES).map(function(k) {
            var t = REQUEST_TEMPLATES[k];
            var methodColor = t.method === "GET" ? "#22c55e" : (t.method === "POST" ? "#3b82f6" : (t.method === "DELETE" ? "#ef4444" : "#f59e0b"));
            return '<button class="btn sm ghost at-tpl" data-tpl="' + esc(k) + '" style="text-align:left;padding:10px">' +
              '<div style="display:flex;align-items:center;gap:6px"><span style="color:' + methodColor + ';font-weight:700;font-size:.72rem">' + esc(t.method) + '</span> <span style="font-weight:600">' + esc(k) + '</span></div>' +
              '<div style="font-size:.72rem;color:var(--mut);margin-top:2px;font-family:var(--mono,monospace);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + esc(t.url) + '</div>' +
            '</button>';
          }).join("") +
        '</div>';

      content.querySelectorAll(".at-tpl").forEach(function(b) {
        b.onclick = function() {
          var tpl = REQUEST_TEMPLATES[b.dataset.tpl];
          if (tpl) {
            renderTab("request");
            setTimeout(function() {
              var urlInput = content.querySelector("#at-url");
              var methodSel = content.querySelector("#at-method");
              var bodyArea = content.querySelector("#at-body");
              if (urlInput) urlInput.value = tpl.url;
              if (methodSel) methodSel.value = tpl.method;
              if (bodyArea) bodyArea.value = tpl.body || "";
            }, 50);
          }
        };
      });

    } else if (tabId === "curl") {
      content.innerHTML =
        '<h2 class="pg-h2">cURL Import / Export</h2>' +
        '<p class="muted" style="font-size:.82rem">Paste a cURL command to import, or generate a cURL command from your current request.</p>' +
        '<textarea class="tk-in" id="at-curl-input" rows="6" placeholder="curl -X POST https://api.example.com/data -H \'Content-Type: application/json\' -d \'{&quot;key&quot;:&quot;value&quot;}\'"></textarea>' +
        '<div class="tk-btns">' +
          '<button class="btn sm" id="at-curl-import">Import to Builder</button>' +
          '<button class="btn sm ghost" id="at-curl-export">Generate cURL from Last Request</button>' +
        '</div>' +
        '<pre class="tk-out" id="at-curl-output" style="margin-top:8px"></pre>';

      content.querySelector("#at-curl-import").onclick = function() {
        var text = content.querySelector("#at-curl-input").value;
        var parsed = parseCurl(text);
        if (!parsed || !parsed.url) {
          content.querySelector("#at-curl-output").textContent = "Could not parse cURL command.";
          return;
        }
        content.querySelector("#at-curl-output").textContent = "Parsed: " + parsed.method + " " + parsed.url + "\nHeaders: " + parsed.headers.length + "\nBody: " + (parsed.body ? "present" : "none") + "\n\nSwitch to Request Builder tab to use.";
        renderTab("request");
        setTimeout(function() {
          var urlInput = content.querySelector("#at-url");
          var methodSel = content.querySelector("#at-method");
          var bodyArea = content.querySelector("#at-body");
          if (urlInput) urlInput.value = parsed.url;
          if (methodSel) methodSel.value = parsed.method;
          if (bodyArea && parsed.body) bodyArea.value = parsed.body;
        }, 50);
      };

      content.querySelector("#at-curl-export").onclick = function() {
        if (history.length) {
          var last = history[0];
          content.querySelector("#at-curl-output").textContent = toCurl(last.method, last.url, [], "");
        } else {
          content.querySelector("#at-curl-output").textContent = "No requests in history yet.";
        }
      };

    } else if (tabId === "env") {
      var envEntries = Object.keys(envVars);
      content.innerHTML =
        '<h2 class="pg-h2">Environment Variables</h2>' +
        '<p class="muted" style="font-size:.82rem">Define variables like {{base_url}}, {{token}} to substitute in URLs, headers, and body.</p>' +
        '<div id="at-env-list" style="margin:12px 0">' +
          envEntries.map(function(k) {
            return '<div style="display:flex;gap:6px;margin-bottom:4px">' +
              '<input class="tk-f at-env-k" value="' + esc(k) + '" placeholder="Variable name" style="flex:1" readonly>' +
              '<input class="tk-f at-env-v" data-key="' + esc(k) + '" value="' + esc(envVars[k]) + '" placeholder="Value" style="flex:2">' +
              '<button class="btn sm danger at-env-del" data-key="' + esc(k) + '" style="padding:2px 8px">X</button>' +
            '</div>';
          }).join("") +
        '</div>' +
        '<div style="display:flex;gap:6px">' +
          '<input class="tk-f" id="at-env-new-k" placeholder="Variable name (e.g. base_url)">' +
          '<input class="tk-f" id="at-env-new-v" placeholder="Value">' +
          '<button class="btn sm" id="at-env-add">Add</button>' +
        '</div>';

      content.querySelectorAll(".at-env-v").forEach(function(inp) {
        inp.oninput = function() { envVars[inp.dataset.key] = inp.value; saveEnv(); };
      });
      content.querySelectorAll(".at-env-del").forEach(function(btn) {
        btn.onclick = function() { delete envVars[btn.dataset.key]; saveEnv(); renderTab("env"); };
      });
      content.querySelector("#at-env-add").onclick = function() {
        var k = content.querySelector("#at-env-new-k").value.trim();
        var v = content.querySelector("#at-env-new-v").value;
        if (k) { envVars[k] = v; saveEnv(); renderTab("env"); }
      };

    } else if (tabId === "collections") {
      content.innerHTML =
        '<h2 class="pg-h2">Collections</h2>' +
        '<p class="muted" style="font-size:.82rem">Save and organize requests into collections. Stored in browser localStorage.</p>' +
        '<div style="display:flex;gap:6px;margin:12px 0">' +
          '<input class="tk-f" id="at-coll-name" placeholder="Collection name">' +
          '<button class="btn sm" id="at-coll-add">Create Collection</button>' +
        '</div>' +
        '<div id="at-coll-list">' +
          (collections.length ? collections.map(function(c, i) {
            return '<div style="border:1px solid var(--line);border-radius:6px;padding:10px;margin-bottom:8px">' +
              '<div style="display:flex;justify-content:space-between;align-items:center">' +
                '<strong>' + esc(c.name) + '</strong>' +
                '<span style="color:var(--mut);font-size:.72rem">' + (c.requests || []).length + ' requests</span>' +
              '</div>' +
              (c.requests && c.requests.length ? c.requests.map(function(r) {
                var mc = r.method === "GET" ? "#22c55e" : "#3b82f6";
                return '<div style="font-size:.78rem;padding:4px 0;font-family:var(--mono,monospace)"><span style="color:' + mc + '">' + esc(r.method) + '</span> ' + esc(r.url) + '</div>';
              }).join("") : '<div style="color:var(--mut);font-size:.78rem">No requests yet</div>') +
              '<button class="btn sm danger at-coll-del" data-idx="' + i + '" style="margin-top:6px;padding:2px 8px;font-size:.72rem">Delete Collection</button>' +
            '</div>';
          }).join("") : '<div style="color:var(--mut);padding:12px;text-align:center">No collections yet.</div>') +
        '</div>';

      content.querySelector("#at-coll-add").onclick = function() {
        var name = content.querySelector("#at-coll-name").value.trim();
        if (name) { collections.push({ name: name, requests: [] }); saveCollections(); renderTab("collections"); }
      };
      content.querySelectorAll(".at-coll-del").forEach(function(btn) {
        btn.onclick = function() { collections.splice(parseInt(btn.dataset.idx), 1); saveCollections(); renderTab("collections"); };
      });
    }
  }

  tabBar.onclick = function(e) {
    var b = e.target.closest(".tab");
    if (b) renderTab(b.dataset.tab);
  };
  renderTab("request");
}
