// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// LEAKPROBE engine — pure, deterministic logic for the Secret Exposure &
// Backend Leak scanner. No DOM, no network; the UI (leakprobe.js) does the real
// I/O through the Darknode proxy and feeds raw bytes/headers in here.
//
// It answers one question with evidence: can a real secret (e.g. a Gemini API
// key) be reached from the browser, or is it kept server-side? It REUSES the DLP
// detector catalogue (dlp-engine.js) as its matching core and adds:
//   - asset discovery from an HTML document and JS module graph,
//   - source-map original-source extraction,
//   - an owner-supplied exact-secret "needle" scan,
//   - placement classification (client-exposed / backend-leaked / server-only),
//   - backend-hygiene grading (CORS, verbose errors, debug routes).
//
// Cross-imports use a relative specifier so node's test runner resolves them.

import { scan as dlpScan, maskValue, shannonEntropy } from "./dlp-engine.js";

/* ------------------------------------------------------------------ helpers */

function abs(ref, base) {
  try { return new URL(ref, base).href; } catch (_) { return null; }
}

// Line/column for an absolute offset into text (1-indexed).
function locate(text, offset) {
  let line = 1, last = 0;
  for (let i = 0; i < offset && i < text.length; i++) {
    if (text[i] === "\n") { line++; last = i + 1; }
  }
  return { line, col: offset - last + 1 };
}

/* -------------------------------------------------- asset graph extraction */

// Discover everything a browser would load from one HTML document. Pure string
// parsing (no DOMParser) so it runs in node. baseUrl resolves relative refs.
// Returns absolute, de-duplicated URL lists by kind.
export function assetGraph(html, baseUrl) {
  html = String(html || "");
  const out = { scripts: [], modules: [], styles: [], links: [], sourceMaps: [], configs: [], inline: [], sw: [] };
  const seen = new Set();
  const add = (list, url) => { if (url && !seen.has(list + "|" + url)) { seen.add(list + "|" + url); out[list].push(url); } };

  // <script ...> blocks (src or inline)
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = scriptRe.exec(html))) {
    const attrs = m[1] || "";
    const src = (attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i) || [])[1];
    const type = (attrs.match(/\btype\s*=\s*["']([^"']+)["']/i) || [])[1] || "";
    if (src) {
      const u = abs(src, baseUrl);
      if (/\bmodule\b/i.test(type)) add("modules", u); else add("scripts", u);
      if (/serviceworker|sw\.js|service-worker/i.test(src)) add("sw", u);
    } else if (m[2] && m[2].trim()) {
      if (/^application\/(ld\+)?json/i.test(type)) out.configs.push({ kind: "inline-json", text: m[2] });
      else out.inline.push({ kind: "inline-script", text: m[2] });
    }
  }
  // self-contained <script src ... /> (rare, no close tag) — also catch void form
  const voidRe = /<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*\/>/gi;
  while ((m = voidRe.exec(html))) add("scripts", abs(m[1], baseUrl));

  // <link rel="modulepreload|preload|stylesheet|manifest">
  const linkRe = /<link\b([^>]*)>/gi;
  while ((m = linkRe.exec(html))) {
    const a = m[1] || "";
    const rel = ((a.match(/\brel\s*=\s*["']([^"']+)["']/i) || [])[1] || "").toLowerCase();
    const href = (a.match(/\bhref\s*=\s*["']([^"']+)["']/i) || [])[1];
    if (!href) continue;
    const u = abs(href, baseUrl);
    if (rel.includes("modulepreload")) add("modules", u);
    else if (rel.includes("stylesheet")) add("styles", u);
    else if (rel.includes("preload")) add("links", u);
    else if (rel.includes("manifest")) add("configs", u);
  }

  // service-worker registration in inline/linked scripts
  const swRe = /navigator\.serviceWorker\.register\(\s*["']([^"']+)["']/gi;
  while ((m = swRe.exec(html))) add("sw", abs(m[1], baseUrl));

  // common config/env endpoints a site may serve
  for (const p of ["/config.js", "/config.json", "/env.js", "/env.json", "/manifest.json", "/sw.js"]) {
    add("configs", abs(p, baseUrl));
  }
  return out;
}

// Extract static + dynamic ES-module import targets (string-literal only).
export function extractImports(jsText, baseUrl) {
  jsText = String(jsText || "");
  const urls = new Set();
  const push = (s) => { const u = abs(s, baseUrl); if (u) urls.add(u); };
  // import ... from "x";  export ... from "x";  import "x";
  const re1 = /\b(?:import|export)\b[^'";]*?\bfrom\s*["']([^"']+)["']/g;
  const re2 = /\bimport\s*["']([^"']+)["']/g;
  const re3 = /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g;
  let m;
  while ((m = re1.exec(jsText))) push(m[1]);
  while ((m = re2.exec(jsText))) push(m[1]);
  while ((m = re3.exec(jsText))) push(m[1]);
  return [...urls];
}

// The //# sourceMappingURL=... reference at the tail of a JS/CSS file, if any.
export function extractSourceMapUrl(jsText, baseUrl) {
  // Take the LAST sourceMappingURL, not the first: the real annotation sits at the file
  // tail, and an earlier occurrence (in a string literal or comment) must not win over it.
  const re = /[#@]\s*sourceMappingURL\s*=\s*(\S+)/g;
  let m, last = null;
  while ((m = re.exec(String(jsText || "")))) last = m;
  if (!last) return null;
  const ref = last[1].trim();
  if (/^data:/i.test(ref)) return { inlineData: ref };          // inline map (base64)
  return { url: abs(ref, baseUrl) };
}

// Pull original sources out of a parsed source map (object or JSON string).
export function parseSourceMap(map) {
  let obj = map;
  if (typeof map === "string") { try { obj = JSON.parse(map); } catch (_) { return []; } }
  if (!obj || typeof obj !== "object") return [];
  const sources = Array.isArray(obj.sources) ? obj.sources : [];
  const content = Array.isArray(obj.sourcesContent) ? obj.sourcesContent : [];
  const out = [];
  for (let i = 0; i < sources.length; i++) {
    if (content[i]) out.push({ source: sources[i] || ("source-" + i), content: content[i] });
  }
  return out;
}

/* ----------------------------------------------------- owner-needle scan */

// Find exact owner-supplied secrets ("needles") in text, case-sensitive,
// with masked evidence and location. This catches a specific key (e.g. the
// real Gemini key) even if it does not match a generic detector pattern.
export function needleScan(text, needles) {
  text = String(text || "");
  const list = (needles || []).map((s) => String(s || "").trim()).filter((s) => s.length >= 8);
  const out = [];
  for (const needle of list) {
    let from = 0, idx;
    while ((idx = text.indexOf(needle, from)) !== -1) {
      const loc = locate(text, idx);
      out.push({
        id: "owner-secret", label: "Tracked secret", kind: "secret", severity: "critical",
        value: needle, masked: maskValue(needle), start: idx, end: idx + needle.length,
        line: loc.line, col: loc.col,
        advice: "This is a secret you asked LEAKPROBE to track. It must never be reachable from a browser.",
      });
      from = idx + needle.length;
    }
  }
  return out;
}

// Named credential detectors worth scanning a minified bundle for. High-entropy
// and PII (email/ip/phone/card/iban/ssn) are deliberately excluded here: they
// generate thousands of false positives in minified JS and source maps and are
// not what a secret-exposure scan is about.
export const BUNDLE_DETECTORS = [
  "private-key", "aws-secret", "aws-key", "gcp-key", "github-token", "github-pat-fine",
  "slack-token", "stripe-key", "openai-key", "anthropic-key", "google-oauth", "jwt",
  "slack-webhook", "twilio-key", "sendgrid-key", "pat-assignment", "conn-string",
];
// Backend responses are small, so high-entropy there is meaningful (a real token
// in a JSON body), but PII is still noise for a leak scan.
export const BACKEND_DETECTORS = BUNDLE_DETECTORS.concat(["high-entropy"]);

// Google API keys (AIza…) and generic api-key assignments are commonly legitimate
// and PUBLIC in client bundles (e.g. the Firebase Web config key), so a client-side
// hit is not automatically critical — it is surfaced as a review/warning instead.
// A pasted owner needle resolves the ambiguity definitively.
export const AMBIGUOUS_CLIENT = new Set(["gcp-key", "pat-assignment", "jwt"]);

// Scan one fetched asset/body for both generic secrets (DLP) and owner needles.
// `opts.detectors` narrows the DLP detector set (see BUNDLE/BACKEND_DETECTORS).
// Returns a flat findings array tagged with the location descriptor `where`.
export function scanBytes(text, where, needles, opts) {
  const r = dlpScan(String(text || ""), opts && opts.detectors ? { detectors: opts.detectors } : {});
  const findings = r.findings.map((f) => ({ ...f, where }));
  for (const n of needleScan(text, needles)) findings.push({ ...n, where });
  return findings;
}

/* --------------------------------------------------- placement classify */

// Rank the worst place a tracked secret (or any secret) was observed.
// Any client-reachable location is critical; backend echo is critical;
// a config/source-map reachable copy is a warning; nothing observed = pass.
const WHERE_RANK = {
  "client-asset": 4, "source-map": 4, "client-request": 4, "backend-response": 4,
  "backend-error": 3, "config-route": 2, "debug-route": 2,
};

export function classifyPlacement(hits) {
  const list = Array.isArray(hits) ? hits : [];
  if (!list.length) {
    return {
      level: "pass",
      label: "Server-side only",
      reason: "No copy of this secret was observed in anything the scanner could reach from the client or in any backend response. As far as observable, it is kept server-side (e.g. in the Cloudflare worker's environment) and not exposed. This is not a proof of absolute safety.",
    };
  }
  let worst = list[0];
  for (const h of list) if ((WHERE_RANK[h.where] || 1) > (WHERE_RANK[worst.where] || 1)) worst = h;
  const w = worst.where;
  if (w === "client-asset" || w === "source-map" || w === "client-request") {
    return {
      level: "critical", label: "Client-exposed",
      reason: "Found in something the browser downloads or sends (" + w + "). Anyone loading the site can read it. Rotate the secret now and move it server-side.",
    };
  }
  if (w === "backend-response") {
    return {
      level: "critical", label: "Backend-leaked",
      reason: "Not in the client bundle, but a backend response returns it. Rotate the secret and stop the backend from echoing it.",
    };
  }
  return {
    level: "warning", label: "Reachable via " + w,
    reason: "Found in a backend error, debug route, config file or source map. Not on the main page, but still reachable. Remove it and verify.",
  };
}

/* -------------------------------------------------------- backend hygiene */

// Grade CORS exposure for an authed/secret-bearing endpoint.
// `headers` is a lower-cased header map; `origin` is the Origin we sent.
export function gradeCors(headers, origin) {
  const h = lc(headers);
  const acao = h["access-control-allow-origin"];
  const acac = String(h["access-control-allow-credentials"] || "").toLowerCase() === "true";
  if (!acao) return { level: "pass", label: "No cross-origin access", reason: "No Access-Control-Allow-Origin header; other origins cannot read responses." };
  if (acao === "*" && acac) {
    return { level: "critical", label: "Wildcard CORS with credentials", reason: "ACAO:* together with credentials is invalid and dangerous — any site could read authenticated responses." };
  }
  if (acao === "*") {
    return { level: "warning", label: "Wildcard CORS", reason: "ACAO:* lets any origin read responses. Safe only if nothing here is sensitive or credentialed." };
  }
  if (origin && acao.toLowerCase() === String(origin).toLowerCase() && acac) {
    return { level: "warning", label: "Origin reflected with credentials", reason: "The backend reflected our arbitrary Origin and allows credentials — effectively open CORS. Pin to an allowlist." };
  }
  return { level: "pass", label: "Scoped CORS", reason: "Access-Control-Allow-Origin is set to a specific origin, not a wildcard." };
}

// Grade how much an error/response body leaks about the backend.
export function gradeErrorLeak(body) {
  const text = String(body || "");
  const signals = [];
  const secrets = dlpScan(text).findings.filter((f) => f.kind === "secret");
  if (secrets.length) signals.push({ kind: "secret", detail: secrets.length + " secret-shaped value(s) in the response", severity: "critical" });
  if (/(?:\/[\w.-]+){2,}\.(?:js|ts|mjs|py|rb|go|php|java):\d+/.test(text) || /\bat\s+[\w$.<>]+\s+\(.+:\d+:\d+\)/.test(text)) {
    signals.push({ kind: "stack", detail: "Stack trace / source line numbers exposed", severity: "high" });
  }
  if (/(?:\/(?:home|usr|var|opt|root|app|srv)\/[\w./-]+)/.test(text)) {
    signals.push({ kind: "path", detail: "Absolute server file path(s) exposed", severity: "medium" });
  }
  const envAssign = text.match(/\b[A-Z][A-Z0-9_]{2,}\s*[:=]\s*\S/g) || [];
  if (envAssign.some((a) => /KEY|TOKEN|SECRET|PASSWORD|PASSWD|DATABASE|API|CREDENTIAL|PRIVATE/.test(a))) {
    signals.push({ kind: "env", detail: "Environment-variable-shaped config in the response", severity: "high" });
  }
  if (/\b(express|flask|django|rails|laravel|nest|fastapi|spring)\b/i.test(text) && /\b(error|exception|traceback|stack)\b/i.test(text)) {
    signals.push({ kind: "framework", detail: "Framework error page / banner exposed", severity: "low" });
  }
  const rank = { critical: 4, high: 3, medium: 2, low: 1 };
  let level = "pass";
  for (const s of signals) if ((rank[s.severity] || 0) > (rank[level] || 0)) level = s.severity;
  if (level === "pass") level = signals.length ? "low" : "pass";
  return { level, signals };
}

/* --------------------------------------------- service / integration intel */

// Signatures for third-party services and backends a site commonly wires in.
// Detected from the client bundle — this is the "what is enabled" inventory a
// business wants, derived from exact client-side evidence (no guessing).
const SERVICE_SIGS = [
  { name: "Firebase", category: "Backend (BaaS)", re: /firebaseConfig|firebaseapp\.com|firebaseio\.com|firebasestorage\.googleapis|firebase\/(?:app|auth|firestore)/i, implication: "Google Firebase backend. Inspect the firebaseConfig to see which products are enabled; secure with Firebase Security Rules and API-key restrictions." },
  { name: "Firebase Auth", category: "Identity", re: /identitytoolkit|authDomain\s*[:=]|firebase\/auth|signInWith/i, implication: "User sign-in is handled by Firebase Authentication. Review enabled providers and authorized domains." },
  { name: "Cloud Firestore", category: "Database", re: /firestore\.googleapis|firebaseio\.com|firebase\/firestore|collection\(/i, implication: "Firestore database in use. Everything is exposed to the client, so access MUST be enforced by Security Rules, not client code." },
  { name: "Firebase Storage", category: "Storage", re: /storageBucket\s*[:=]|firebasestorage\.googleapis/i, implication: "Firebase Cloud Storage bucket referenced. Lock down with Storage Security Rules." },
  { name: "Firebase Cloud Messaging", category: "Messaging", re: /messagingSenderId\s*[:=]|fcm\.googleapis/i, implication: "Push messaging (FCM) is configured." },
  { name: "Google OAuth / Sign-In", category: "Identity", re: /\.apps\.googleusercontent\.com|accounts\.google\.com\/gsi|google\.accounts\.oauth2/i, implication: "Google OAuth / Google Sign-In is enabled. The client_id is public; the client SECRET (GOCSPX-) must never appear client-side." },
  { name: "Stripe", category: "Payments", re: /js\.stripe\.com|\bpk_(?:live|test)_|Stripe\(/i, implication: "Stripe payments. The publishable key (pk_) is public; a secret key (sk_) client-side is a critical leak." },
  { name: "Sentry", category: "Observability", re: /@o\d+\.ingest(?:\.[a-z]+)?\.sentry\.io|sentry\.io\/\d|Sentry\.init/i, implication: "Sentry error monitoring. The DSN is semi-public; ensure it is not a server/auth token." },
  { name: "Google Analytics / Tag Manager", category: "Analytics", re: /googletagmanager\.com|\bG-[A-Z0-9]{8,}\b|\bGTM-[A-Z0-9]+\b|gtag\(/i, implication: "Google Analytics / GTM tracking is loaded." },
  { name: "reCAPTCHA", category: "Anti-abuse", re: /recaptcha|grecaptcha|\b6L[0-9A-Za-z_-]{20,}\b/i, implication: "Google reCAPTCHA. The site key is public by design." },
  { name: "Cloudflare", category: "CDN / Edge", re: /challenges\.cloudflare\.com|\/cdn-cgi\/|workers\.dev/i, implication: "Fronted by Cloudflare (CDN / Workers / Turnstile)." },
  { name: "Supabase", category: "Backend (BaaS)", re: /supabase\.co|supabaseKey|createClient\(\s*["']https?:\/\/[a-z0-9]+\.supabase/i, implication: "Supabase backend. The anon key is public but RLS policies must enforce access; a service_role key client-side is critical." },
  { name: "Auth0", category: "Identity", re: /\.auth0\.com|auth0-spa-js|@auth0\//i, implication: "Auth0 identity provider." },
  { name: "AWS Amplify / Cognito", category: "Backend (BaaS)", re: /cognito-idp\.|amazon(?:aws)?\.com\/.*cognito|aws-amplify|amplifyconfiguration/i, implication: "AWS Amplify / Cognito. Check user-pool and identity-pool exposure." },
  { name: "Mapbox", category: "Maps", re: /api\.mapbox\.com|\bpk\.eyJ[\w-]+/i, implication: "Mapbox. The public token (pk.) should be URL-restricted; a secret token (sk.) is a leak." },
  { name: "Algolia", category: "Search", re: /algolia(?:net)?\.com|algoliasearch|X-Algolia-API-Key/i, implication: "Algolia search. The search-only API key is public; an admin key client-side is critical." },
  { name: "Segment", category: "Analytics", re: /cdn\.segment\.com|analytics\.(?:track|identify)\(/i, implication: "Segment analytics pipeline." },
  { name: "Mixpanel", category: "Analytics", re: /cdn\.mxpnl\.com|mixpanel\.init/i, implication: "Mixpanel analytics." },
  { name: "Intercom", category: "Support", re: /widget\.intercom\.io|intercomSettings/i, implication: "Intercom messaging widget." },
  { name: "Datadog", category: "Observability", re: /datadoghq|DD_RUM|datadog-rum/i, implication: "Datadog RUM / monitoring." },
  { name: "PostHog", category: "Analytics", re: /posthog\.(?:com|init)|ph_project_api_key/i, implication: "PostHog product analytics." },
  { name: "OpenAI (client-side)", category: "AI", re: /api\.openai\.com/i, implication: "The browser talks to the OpenAI API directly — the key would be exposed. AI calls should be proxied server-side." },
  { name: "Anthropic (client-side)", category: "AI", re: /api\.anthropic\.com/i, implication: "The browser talks to the Anthropic API directly — the key would be exposed. AI calls should be proxied server-side." },
  { name: "Google Generative Language (client-side)", category: "AI", re: /generativelanguage\.googleapis\.com/i, implication: "The browser talks to the Gemini / Generative Language API directly — the key would be exposed. Proxy AI calls server-side." },
];

// Detect services referenced in one chunk of client text. `source` is where it
// came from (for evidence). Returns [{name, category, implication, source}].
export function detectServices(text, source) {
  const t = String(text || "");
  const out = [];
  for (const s of SERVICE_SIGS) { if (s.re.test(t)) out.push({ name: s.name, category: s.category, implication: s.implication, source: source || "" }); }
  return out;
}

// Merge detections (from many assets) into a map keyed by service name,
// collecting the distinct sources that evidenced each.
export function mergeServices(map, detections) {
  for (const d of detections || []) {
    const cur = map.get(d.name) || { name: d.name, category: d.category, implication: d.implication, sources: new Set() };
    if (d.source) cur.sources.add(d.source);
    map.set(d.name, cur);
  }
  return map;
}

// Parse a firebaseConfig-style object literal out of bundle text and report
// which Firebase products are enabled from the fields present.
export function parseFirebaseConfig(text) {
  const t = String(text || "");
  const grab = (k) => { const m = t.match(new RegExp(k + "\\s*[:=]\\s*[\"']([^\"']+)[\"']")); return m ? m[1] : null; };
  const cfg = {
    apiKey: grab("apiKey"), authDomain: grab("authDomain"), projectId: grab("projectId"),
    storageBucket: grab("storageBucket"), messagingSenderId: grab("messagingSenderId"),
    appId: grab("appId"), measurementId: grab("measurementId"),
  };
  if (!cfg.projectId && !cfg.authDomain && !cfg.apiKey) return null;
  const products = [];
  if (cfg.authDomain) products.push("Authentication");
  if (cfg.projectId) products.push("Cloud Firestore / Realtime DB");
  if (cfg.storageBucket) products.push("Cloud Storage");
  if (cfg.messagingSenderId) products.push("Cloud Messaging (FCM)");
  if (cfg.measurementId) products.push("Analytics");
  return { config: cfg, products };
}

// Classify a secret/key finding: which provider, is it meant to be public,
// and is this placement insecure. Drives the "API keys" intelligence table.
export function classifyKey(finding) {
  const id = finding.id, v = String(finding.value || finding.masked || "");
  const onClient = finding.where === "client-asset" || finding.where === "source-map" || finding.where === "client-request";
  const SECRET = (provider, note) => ({ provider, exposure: "secret", insecure: onClient, note: note || "Secret-type key. If it is in the client bundle it is exposed to everyone — rotate and move server-side." });
  const PUBLIC = (provider, note) => ({ provider, exposure: "public", insecure: false, note: note || "Public/publishable identifier — safe client-side when properly restricted." });
  const REVIEW = (provider, note) => ({ provider, exposure: "review", insecure: false, note });
  switch (id) {
    case "aws-secret": return SECRET("AWS");
    case "aws-key": return SECRET("AWS", "AWS access key id. Treat as secret; should not be client-side.");
    case "openai-key": return SECRET("OpenAI");
    case "anthropic-key": return SECRET("Anthropic");
    case "google-oauth": return SECRET("Google OAuth client secret");
    case "github-token": case "github-pat-fine": return SECRET("GitHub");
    case "slack-token": case "slack-webhook": return SECRET("Slack");
    case "stripe-key": return /^sk_/.test(v) ? SECRET("Stripe", "Stripe SECRET key — critical if client-side.") : PUBLIC("Stripe", "Stripe publishable key (pk_) — public by design.");
    case "twilio-key": return SECRET("Twilio");
    case "sendgrid-key": return SECRET("SendGrid");
    case "private-key": return SECRET("Private key", "A private key block. Must never be client-side.");
    case "conn-string": return SECRET("Database", "Database connection string with embedded credentials.");
    case "gcp-key": return REVIEW("Google", "Google API key (AIza…). Public identifier, but INSECURE if unrestricted — lock it to HTTP referrers and specific APIs in the Cloud console. If it is a Gemini/Generative-Language key, it must be server-side only.");
    case "jwt": return REVIEW("JWT", "A JSON Web Token. May be a public anon key (e.g. Supabase) or a leaked session/service token — verify its claims and role.");
    case "pat-assignment": return REVIEW("Generic", "An api-key / token / password assignment. Confirm whether the value is a real secret or a public config key.");
    case "owner-secret": return SECRET("Tracked secret", "A secret you asked to track. Must never be client-reachable.");
    default: return REVIEW("Unknown", "High-entropy value — confirm whether it is a secret.");
  }
}

// Small, SAFE wordlist of routes that commonly leak config/secrets if present.
// GET-only, bounded; the UI rate-limits and the consent gate precedes it.
export function commonDebugRoutes() {
  return [
    "/.env", "/.env.local", "/.env.production",
    "/.git/HEAD", "/.git/config",
    "/config.json", "/config.js", "/env.json", "/__env", "/__env.js",
    "/debug", "/status?debug=1", "/health?verbose=1",
    "/actuator/env", "/server-status", "/phpinfo.php",
    "/cdn-cgi/trace",
  ];
}

// Judge whether a probed route response looks like a real leak (vs a 404/SPA).
export function gradeRouteResponse(route, status, body) {
  const text = String(body || "");
  if (status == null || status >= 400 || status === 0) return { hit: false };
  // An SPA that returns index.html for everything is not a leak.
  if (/<!doctype html>/i.test(text.slice(0, 200)) && /<div id="?(?:root|app|view)"?/i.test(text)) return { hit: false };
  const secrets = dlpScan(text).findings.filter((f) => f.kind === "secret");
  const envish = /\b(KEY|TOKEN|SECRET|PASSWORD|DATABASE_URL|API_KEY)\b\s*[:=]/.test(text);
  const gitish = /^ref:\s|\[core\]|repositoryformatversion/m.test(text);
  if (secrets.length || envish || gitish) {
    return { hit: true, severity: secrets.length ? "critical" : "high", detail: secrets.length ? (secrets.length + " secret(s) returned") : (gitish ? "Git metadata served" : "Config/env content served"), route };
  }
  return { hit: false };
}

/* ------------------------------------------------------------ scoring */

// Roll all findings into one headline, counting by severity and location.
export function scoreExposure(findings) {
  const list = Array.isArray(findings) ? findings : [];
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byWhere = {};
  for (const f of list) {
    if (bySeverity[f.severity] != null) bySeverity[f.severity]++;
    const w = f.where || "unknown";
    byWhere[w] = (byWhere[w] || 0) + 1;
  }
  const onClient = (f) => f.where === "client-asset" || f.where === "source-map" || f.where === "client-request";
  // An unambiguous credential in the client bundle is critical; an ambiguous one
  // (Google API key / generic api-key assignment / JWT) is a warning, not a verdict.
  const clientExposed = list.some((f) => f.kind === "secret" && !AMBIGUOUS_CLIENT.has(f.id) && onClient(f));
  const clientAmbiguous = list.some((f) => f.kind === "secret" && AMBIGUOUS_CLIENT.has(f.id) && onClient(f));
  const backendLeaked = list.some((f) => f.kind === "secret" && f.where === "backend-response");
  let grade = "clean";
  if (clientExposed || backendLeaked || bySeverity.critical) grade = "critical";
  else if (bySeverity.high || clientAmbiguous) grade = "high";
  else if (bySeverity.medium) grade = "elevated";
  else if (bySeverity.low) grade = "low";
  return {
    grade, bySeverity, byWhere,
    total: list.length,
    secrets: list.filter((f) => f.kind === "secret").length,
    clientExposed, clientAmbiguous, backendLeaked,
  };
}

function lc(headers) {
  const o = {};
  if (headers && typeof headers === "object") {
    for (const k of Object.keys(headers)) o[String(k).toLowerCase()] = headers[k];
  }
  return o;
}

/* ------------------------------------------------------------- self test */

export function selfTest() {
  const tests = [];
  const T = (name, cond) => tests.push({ name, pass: !!cond });

  const html = `<!doctype html><html><head>
    <link rel="modulepreload" href="/js/app.mjs">
    <link rel="stylesheet" href="/css/main.css">
    <script src="/js/vendor.js"></script>
    <script type="module" src="/js/main.mjs"></script>
    <script type="application/json">{"k":"v"}</script>
    <script>console.log('inline')</script>
    </head><body></body></html>`;
  const g = assetGraph(html, "https://x.test/");
  T("assetGraph finds classic script", g.scripts.includes("https://x.test/js/vendor.js"));
  T("assetGraph finds module (src + modulepreload)", g.modules.includes("https://x.test/js/main.mjs") && g.modules.includes("https://x.test/js/app.mjs"));
  T("assetGraph finds stylesheet", g.styles.includes("https://x.test/css/main.css"));
  T("assetGraph captures inline script", g.inline.some((i) => /inline/.test(i.text)));

  const imps = extractImports('import a from "./a.js"; export {x} from "../b.mjs"; import("/c.js"); import "/d.js";', "https://x.test/js/");
  T("extractImports resolves static+dynamic", imps.includes("https://x.test/js/a.js") && imps.includes("https://x.test/b.mjs") && imps.includes("https://x.test/c.js") && imps.includes("https://x.test/d.js"));

  const sm = extractSourceMapUrl("code();\n//# sourceMappingURL=app.js.map", "https://x.test/js/app.js");
  T("extractSourceMapUrl resolves", sm && sm.url === "https://x.test/js/app.js.map");

  const srcs = parseSourceMap({ sources: ["a.ts", "b.ts"], sourcesContent: ["const K='AIzaSyA';", null] });
  T("parseSourceMap keeps only populated sources", srcs.length === 1 && /AIza/.test(srcs[0].content));

  const needles = needleScan("header\nconst k = 'SUPERSECRET-abc123-value';\nfooter", ["SUPERSECRET-abc123-value"]);
  T("needleScan finds exact secret with line", needles.length === 1 && needles[0].line === 2 && needles[0].masked !== needles[0].value && needles[0].masked.includes("\u2022"));
  T("needleScan ignores short needles", needleScan("tiny abc here", ["abc"]).length === 0);

  T("classifyPlacement pass on empty", classifyPlacement([]).level === "pass");
  T("classifyPlacement critical on client asset", classifyPlacement([{ where: "client-asset" }]).level === "critical");
  T("classifyPlacement critical on backend response", classifyPlacement([{ where: "backend-response" }]).level === "critical" && /Backend-leaked/.test(classifyPlacement([{ where: "backend-response" }]).label));
  T("classifyPlacement warning on debug route only", classifyPlacement([{ where: "debug-route" }]).level === "warning");
  T("classifyPlacement picks worst location", classifyPlacement([{ where: "debug-route" }, { where: "client-asset" }]).level === "critical");

  T("gradeCors flags wildcard+credentials", gradeCors({ "access-control-allow-origin": "*", "access-control-allow-credentials": "true" }).level === "critical");
  T("gradeCors warns on bare wildcard", gradeCors({ "Access-Control-Allow-Origin": "*" }).level === "warning");
  T("gradeCors passes scoped", gradeCors({ "access-control-allow-origin": "https://app.test" }).level === "pass");
  T("gradeCors flags reflected origin with creds", gradeCors({ "access-control-allow-origin": "https://evil.test", "access-control-allow-credentials": "true" }, "https://evil.test").level === "warning");

  const el = gradeErrorLeak("TypeError: x\n    at handler (/usr/src/app/server.js:42:13)\nDATABASE_URL=postgres://u:p@h/db API_KEY set");
  T("gradeErrorLeak catches stack + env", el.signals.some((s) => s.kind === "stack") && el.signals.some((s) => s.kind === "env") && el.level === "critical");
  T("gradeErrorLeak passes clean body", gradeErrorLeak('{"error":"bad request"}').level === "pass");

  T("gradeRouteResponse hit on git head", gradeRouteResponse("/.git/HEAD", 200, "ref: refs/heads/main").hit === true);
  T("gradeRouteResponse ignores SPA fallback", gradeRouteResponse("/debug", 200, '<!doctype html><html><body><div id="root"></div></body></html>').hit === false);
  T("gradeRouteResponse ignores 404", gradeRouteResponse("/.env", 404, "not found").hit === false);

  const sc = scoreExposure([{ id: "openai-key", kind: "secret", severity: "high", where: "client-asset" }]);
  T("scoreExposure marks unambiguous client secret critical", sc.grade === "critical" && sc.clientExposed === true);
  const scg = scoreExposure([{ id: "gcp-key", kind: "secret", severity: "high", where: "client-asset" }]);
  T("scoreExposure treats client-side Google API key as ambiguous warning, not critical", scg.clientExposed === false && scg.clientAmbiguous === true && scg.grade === "high");
  T("scoreExposure clean on empty", scoreExposure([]).grade === "clean");
  T("BUNDLE_DETECTORS excludes high-entropy and PII", !BUNDLE_DETECTORS.includes("high-entropy") && !BUNDLE_DETECTORS.includes("email") && BUNDLE_DETECTORS.includes("gcp-key"));
  T("scanBytes with BUNDLE_DETECTORS drops entropy noise but keeps AI key", (() => {
    const noisy = "var a='" + "ZmFrZUhpZ2hFbnRyb3B5Qmxvb" + "mRvbWluaWZpZWRub2lzZXh5eg" + "'; var k='AIza" + "D".repeat(35) + "';";
    const f = scanBytes(noisy, "client-asset", [], { detectors: BUNDLE_DETECTORS });
    return !f.some((x) => x.id === "high-entropy") && f.some((x) => x.id === "gcp-key");
  })());

  T("scanBytes finds generic AI key + owner needle", (() => {
    const f = scanBytes("var g='AIza" + "B".repeat(35) + "'; var mine='MY-TRACKED-abc12345';", "client-asset", ["MY-TRACKED-abc12345"]);
    return f.some((x) => x.id === "gcp-key" && x.where === "client-asset") && f.some((x) => x.id === "owner-secret");
  })());

  const svc = detectServices("const firebaseConfig={apiKey:'x',authDomain:'a.firebaseapp.com'}; js.stripe.com; accounts.google.com/gsi", "app.js");
  T("detectServices finds firebase, stripe, google-oauth", svc.some((s) => s.name === "Firebase") && svc.some((s) => s.name === "Stripe") && svc.some((s) => /Google OAuth/.test(s.name)));
  const smap = mergeServices(new Map(), svc); mergeServices(smap, detectServices("firebaseapp.com", "b.js"));
  T("mergeServices unions sources", smap.get("Firebase").sources.size === 2);
  const fb = parseFirebaseConfig("firebaseConfig = { apiKey: \"AIzaX\", authDomain: \"p.firebaseapp.com\", projectId: \"p\", storageBucket: \"p.appspot.com\", messagingSenderId: \"123\" }");
  T("parseFirebaseConfig lists enabled products", !!fb && fb.products.includes("Authentication") && fb.products.includes("Cloud Storage") && fb.config.projectId === "p");
  T("classifyKey: openai client-side = insecure secret", (() => { const c = classifyKey({ id: "openai-key", where: "client-asset" }); return c.exposure === "secret" && c.insecure === true; })());
  T("classifyKey: stripe pk public vs sk secret", classifyKey({ id: "stripe-key", value: "pk_live_x", where: "client-asset" }).exposure === "public" && classifyKey({ id: "stripe-key", value: "sk_live_x", where: "client-asset" }).insecure === true);
  T("classifyKey: gcp-key ambiguous review", classifyKey({ id: "gcp-key", where: "client-asset" }).exposure === "review");

  return { pass: tests.every((t) => t.pass), tests };
}

export default {
  assetGraph, extractImports, extractSourceMapUrl, parseSourceMap,
  needleScan, scanBytes, classifyPlacement, gradeCors, gradeErrorLeak,
  commonDebugRoutes, gradeRouteResponse, scoreExposure, selfTest,
  BUNDLE_DETECTORS, BACKEND_DETECTORS, AMBIGUOUS_CLIENT,
  detectServices, mergeServices, parseFirebaseConfig, classifyKey,
};
