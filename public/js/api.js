// Darknode API page. The HOSTED REST API does not exist yet (it ships with the workspace
// ingest API), so this page says so and issues no keys. What does work today is the
// self-hosted server in the Darknode CLI (darknode-cli lib/cli/api-server.js, started with
// `darknode api start`); the endpoints, request bodies and response fields below are the
// ones that server actually implements.

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const BASE = "http://localhost:8080";

const ENDPOINTS = [
  { path: "/api/v1/scan/url", desc: "Header, DNS, certificate and subdomain recon for a URL's host",
    reqBody: { url: "https://example.com" },
    returns: "status, url, host, headers, dns, certificate, subdomains[]" },
  { path: "/api/v1/scan/code", desc: "Pattern scan of a code snippet (eval/exec, SQL concatenation, innerHTML, hardcoded secrets)",
    reqBody: { code: "db.query('SELECT * FROM users WHERE id=' + req.query.id)", language: "javascript" },
    returns: "status, language, findings[] of { severity, title, line, detail }" },
  { path: "/api/v1/osint/domain", desc: "DNS, WHOIS, subdomains and HTTP headers for a domain",
    reqBody: { domain: "example.com" },
    returns: "domain, dns, whois, subdomains[], headers" },
  { path: "/api/v1/osint/email", desc: "DNS records for an email address's domain (no breach lookup)",
    reqBody: { email: "test@darknode.ai" },
    returns: "email, domain, dns, note" },
  { path: "/api/v1/hash/crack", desc: "Digests (MD5, SHA-1, SHA-256, ...) of the input text; it does not crack hashes",
    reqBody: { hash: "hello" },
    returns: "hash, output" },
  { path: "/api/v1/encode", desc: "Encode or decode: base64, hex, url, base32, base58, rot13",
    reqBody: { data: "hello world", operation: "encode", format: "base64" },
    returns: "result, format, operation" },
  { path: "/api/v1/generate/payload", desc: "Reverse-shell payloads for a language with your LHOST/LPORT filled in",
    reqBody: { language: "python", lhost: "10.10.14.1", lport: 4444 },
    returns: "type, language, lhost, lport, output" },
  { path: "/api/v1/ai/ask", desc: "Ask the Nexus AI engine (needs an AI provider configured in the CLI)",
    reqBody: { question: "How do I test for blind SQL injection?" },
    returns: "answer, engine" },
];

const curlFor = (path, body) => `curl -X POST ${BASE}${path} \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: $DARKNODE_API_TOKEN" \\
  -d '${JSON.stringify(body)}'`;

export async function renderAPI(main, user) {
  main.innerHTML = `
    <h1 class="pg-h1">Darknode API</h1>
    <p class="muted pg-sub">The hosted REST API is not available yet &mdash; it ships with the workspace ingest API. The same endpoints run today on your own machine with the Darknode CLI.</p>

    <div class="panel">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Hosted API</h2><span class="muted" style="font-size:.82rem">Not available yet</span></div>
      <p style="font-size:.88rem;line-height:1.7;margin:0">There is no hosted endpoint and there are no hosted API keys yet; they ship with the workspace ingest API. Until then, run the self-hosted server below. It needs no Darknode account.</p>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Self-hosted quick start</h2></div>
      <div class="api-code-block">
        <div class="api-code-header">bash</div>
        <button class="api-code-copy" data-copy="quickstart">Copy</button>
        <pre><code id="quickstart"># Get the Darknode CLI (Node 18+)
git clone https://github.com/Darknode-Official/darknode-cli
cd darknode-cli &amp;&amp; npm install

# Start the API server. Every request must send the token (if you set none, the server makes one and prints it).
export DARKNODE_API_TOKEN="choose-a-long-secret"
node darknode.js api start --port 8080

# In another terminal (export the same DARKNODE_API_TOKEN first)
curl ${BASE}/health -H "X-API-Key: $DARKNODE_API_TOKEN"
${esc(curlFor(ENDPOINTS[0].path, ENDPOINTS[0].reqBody))}</code></pre>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Endpoints (self-hosted)</h2></div>
      <p class="muted" style="font-size:.82rem;margin:0 0 12px">Served by <code>darknode api start</code> on your machine. All take a JSON body; <code>GET /health</code> lists them.</p>
      <div id="apiEndpoints">
        ${ENDPOINTS.map((ep, i) => `
          <div class="api-endpoint" data-idx="${i}">
            <div class="api-ep-header">
              <span class="api-method api-method-post">POST</span>
              <span class="api-path mono">${esc(ep.path)}</span>
              <span class="api-ep-desc muted">${esc(ep.desc)}</span>
              <span class="api-ep-toggle">+</span>
            </div>
            <div class="api-ep-body" style="display:none">
              <div class="api-ep-section">
                <div class="api-ep-label">Request</div>
                <div class="api-code-block">
                  <div class="api-code-header">JSON body</div>
                  <pre><code>${esc(JSON.stringify(ep.reqBody, null, 2))}</code></pre>
                </div>
              </div>
              <div class="api-ep-section">
                <div class="api-ep-label">Response fields</div>
                <p class="mono" style="font-size:.82rem;margin:0">${esc(ep.returns)}</p>
              </div>
              <div class="api-ep-section">
                <div class="api-ep-label">curl</div>
                <div class="api-code-block">
                  <button class="api-code-copy" data-copy="curl-${i}">Copy</button>
                  <pre><code id="curl-${i}">${esc(curlFor(ep.path, ep.reqBody))}</code></pre>
                </div>
              </div>
            </div>
          </div>
        `).join("")}
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Code Examples (self-hosted)</h2></div>
      <div class="api-code-tabs">
        <button class="api-tab on" data-lang="curl">curl</button>
        <button class="api-tab" data-lang="python">Python</button>
        <button class="api-tab" data-lang="javascript">JavaScript</button>
      </div>
      <div class="api-code-block" id="codeExampleBlock">
        <button class="api-code-copy" data-copy="codeExample">Copy</button>
        <pre><code id="codeExample">${esc(curlFor(ENDPOINTS[0].path, ENDPOINTS[0].reqBody))}</code></pre>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Authentication (self-hosted)</h2></div>
      <p style="font-size:.88rem;line-height:1.7">The server checks the <code>X-API-Key</code> header only when it was started with <code>DARKNODE_API_TOKEN</code> set; a missing or wrong key then returns <code>401</code>. Without the variable it accepts every request.</p>
      <p style="font-size:.85rem;line-height:1.7;margin-top:10px">It listens on all interfaces (0.0.0.0), so always set a token on a machine other hosts can reach.</p>
    </div>
  `;

  const $ = (id) => main.querySelector(id);

  // Endpoint toggles
  main.querySelectorAll(".api-endpoint").forEach(ep => {
    const header = ep.querySelector(".api-ep-header");
    const body = ep.querySelector(".api-ep-body");
    const toggle = ep.querySelector(".api-ep-toggle");
    if (header && body) header.onclick = () => {
      const open = body.style.display !== "none";
      body.style.display = open ? "none" : "block";
      if (toggle) toggle.textContent = open ? "+" : "-";
    };
  });

  // Code copy buttons
  main.querySelectorAll(".api-code-copy").forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const targetId = btn.dataset.copy;
      const el = main.querySelector("#" + targetId) || btn.parentElement.querySelector("code");
      if (el) {
        navigator.clipboard?.writeText(el.textContent);
        btn.textContent = "Copied!";
        setTimeout(() => { btn.textContent = "Copy"; }, 1200);
      }
    };
  });

  // Language tabs
  const CODE_EXAMPLES = {
    curl: curlFor(ENDPOINTS[0].path, ENDPOINTS[0].reqBody),

    python: `import os, requests

response = requests.post(
    "${BASE}/api/v1/scan/url",
    headers={"X-API-Key": os.environ.get("DARKNODE_API_TOKEN", "")},
    json={"url": "https://example.com"},
)
print(response.status_code, response.json())`,

    javascript: `// Node 18+
const response = await fetch("${BASE}/api/v1/scan/url", {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-API-Key": process.env.DARKNODE_API_TOKEN || ""
  },
  body: JSON.stringify({ url: "https://example.com" })
});
console.log(response.status, await response.json());`,
  };

  main.querySelectorAll(".api-tab").forEach(tab => {
    tab.onclick = () => {
      main.querySelectorAll(".api-tab").forEach(t => t.classList.remove("on"));
      tab.classList.add("on");
      const code = $("#codeExample");
      if (code) code.textContent = CODE_EXAMPLES[tab.dataset.lang] || "";
    };
  });
}
