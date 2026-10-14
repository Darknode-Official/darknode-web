// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// LEAKPROBE — Secret Exposure & Backend Leak scanner (UI).
//
// Point it at a web property you own. It fetches everything the browser would
// download (HTML, scripts, ES-module graph, source maps, config/sw), scans each
// for secrets (reusing the DLP detectors) plus any exact secret you ask it to
// track (e.g. your Gemini key), then GET-probes the backend endpoints, their
// error pages and a small safe wordlist of debug routes. It rolls the evidence
// into one placement verdict per tracked secret: client-exposed (critical),
// backend-leaked (critical), or server-side only (pass).
//
// All network I/O goes through the Darknode proxy (net.js -> worker /api/fetch),
// which fetches server-side; nothing here calls a provider API or spends a key.
// Scoring and parsing are pure and tested in leakprobe-engine.js.
//
//   renderLeakprobe(main) -> void

import {
  assetGraph, extractSourceMapUrl, parseSourceMap,
  scanBytes, classifyPlacement, gradeCors, gradeErrorLeak,
  commonDebugRoutes, gradeRouteResponse, scoreExposure,
  BUNDLE_DETECTORS, BACKEND_DETECTORS,
} from "/js/dataprotect/leakprobe-engine.js?v=20261013k";
import { dnFetch } from "/js/net.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const LV = {
  critical: { c: "#b00020", t: "Critical" }, warning: { c: "#b58100", t: "Warning" },
  high: { c: "#d9480f", t: "High" }, medium: { c: "#b58100", t: "Medium" },
  low: { c: "#2f7d9e", t: "Low" }, pass: { c: "#2f9e56", t: "Pass" }, clean: { c: "#2f9e56", t: "Clean" },
  elevated: { c: "#b58100", t: "Elevated" },
};

// Caps: keep the scan polite and bounded.
const MAX_ASSETS = 48;
const MAX_CONCURRENCY = 5;
const ASSET_MAX_BYTES = 2_000_000;

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "lp-css";
  st.textContent = `
  .lp{max-width:1100px;margin:0 auto;font-size:14px;line-height:1.5}
  .lp .lp-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .lp h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .lp .lp-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .lp .lp-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:76ch}
  .lp .lp-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .lp label.lp-lab{display:block;font-weight:600;font-size:.82rem;margin:0 0 5px;color:var(--tx,#1a2230)}
  .lp .lp-help{color:var(--mut,#667085);font-size:.78rem;margin:4px 0 0;line-height:1.45}
  .lp input,.lp textarea{width:100%;font:inherit;font-size:.9rem;padding:9px 12px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box}
  .lp textarea{min-height:64px;resize:vertical;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem}
  .lp .lp-row{margin-bottom:12px}
  .lp .lp-consent{display:flex;gap:9px;align-items:flex-start;padding:11px 13px;border:1px solid #f0c36d;background:#fff8e6;border-radius:9px;margin-bottom:14px}
  .lp .lp-consent input{width:auto;margin-top:3px;flex:0 0 auto}
  .lp .lp-consent span{font-size:.82rem;color:#7a5b00;line-height:1.45}
  .lp .lp-btn{appearance:none;font:inherit;font-size:.88rem;font-weight:600;border:1px solid #2552c6;background:#2552c6;color:#fff;padding:10px 20px;border-radius:8px;cursor:pointer}
  .lp .lp-btn:hover{background:#1c42a6}
  .lp .lp-btn:disabled{opacity:.5;cursor:not-allowed}
  .lp .lp-ghost{background:transparent;color:#2552c6;border-color:#c7d2ec}
  .lp .lp-ghost:hover{background:#eef2fb}
  .lp .lp-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:4px}
  .lp .lp-prog{margin:12px 0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;color:var(--mut,#667085);max-height:160px;overflow:auto;white-space:pre-wrap}
  .lp .lp-verdict{display:flex;gap:14px;align-items:center;padding:16px 18px;border-radius:12px;border:1px solid var(--line,#e6e8ee);background:var(--card,#fff);margin-bottom:12px}
  .lp .lp-vchip{flex:0 0 auto;width:92px;text-align:center;padding:10px 6px;border-radius:10px;color:#fff;font-weight:800;font-size:.9rem;letter-spacing:.02em}
  .lp .lp-vbody b{display:block;font-size:1.02rem;margin-bottom:3px}
  .lp .lp-vbody span{color:var(--mut,#667085);font-size:.85rem}
  .lp .lp-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:14px}
  .lp .lp-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:12px 14px}
  .lp .lp-kpi .n{font-size:1.5rem;font-weight:800;line-height:1}
  .lp .lp-kpi .l{color:var(--mut,#667085);font-size:.76rem;margin-top:5px;text-transform:uppercase;letter-spacing:.04em}
  .lp h2{font-size:1.02rem;margin:18px 0 9px}
  .lp table{width:100%;border-collapse:collapse;font-size:.82rem}
  .lp th,.lp td{text-align:left;padding:7px 9px;border-bottom:1px solid var(--line,#eef0f5);vertical-align:top;overflow-wrap:anywhere}
  .lp th{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700}
  .lp .lp-pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.7rem;font-weight:700;color:#fff}
  .lp code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;background:var(--bg,#f3f5f9);padding:1px 5px;border-radius:5px}
  .lp .lp-empty{color:var(--mut,#667085);font-size:.85rem;padding:6px 2px}
  .lp .lp-note{font-size:.78rem;color:var(--mut,#667085);margin-top:14px;line-height:1.5;border-top:1px solid var(--line,#eef0f5);padding-top:12px}
  `;
  (document.head || document.documentElement).appendChild(st);
}

function pill(level) {
  const v = LV[level] || LV.low;
  return `<span class="lp-pill" style="background:${v.c}">${esc(v.t)}</span>`;
}

// Concurrency-limited map over a work list.
async function pool(items, limit, fn) {
  const out = new Array(items.length);
  let i = 0;
  const workers = new Array(Math.min(limit, items.length || 0)).fill(0).map(async () => {
    while (i < items.length) { const idx = i++; try { out[idx] = await fn(items[idx], idx); } catch (e) { out[idx] = { error: (e && e.message) || String(e) }; } }
  });
  await Promise.all(workers);
  return out;
}

export function renderLeakprobe(main) {
  injectStyle();
  // Mirror net.js proxyBase(): DARKNODE_PROXY_URL may carry a trailing /api/chat.
  const pbase = (() => { try { return String(window.DARKNODE_PROXY_URL || "").replace(/\/api\/chat$/, "").replace(/\/$/, ""); } catch (_) { return ""; } })();
  const defaultEndpoints = pbase ? [pbase + "/api/chat", pbase + "/api/smart"].join("\n") : "";

  main.innerHTML = `
  <div class="lp">
    <div class="lp-hd"><h1>Secret Exposure &amp; Backend Leak Scanner</h1><span class="lp-tag">LEAKPROBE</span></div>
    <p class="lp-sub">Prove whether a real secret — an API key, a token, your Gemini key — can be reached from the browser, or is kept server-side. It fetches everything the page downloads (scripts, module graph, source maps, config, service worker), scans each for secrets, then GET-probes your backend endpoints, their error pages and common debug routes. Secrets are masked; nothing is uploaded and no key is ever spent to test it.</p>

    <div class="lp-card">
      <div class="lp-consent">
        <input type="checkbox" id="lpConsent">
        <span><b>Authorized targets only.</b> Tick to confirm you own, or are authorized to test, the target below. LEAKPROBE performs a small number of bounded GET requests through the Darknode proxy. Do not point it at property you do not control.</span>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpUrl" data-explain="lp.target">Target URL</label>
        <input id="lpUrl" type="text" placeholder="https://your-site.example" value="https://darknode.ai" spellcheck="false" autocapitalize="off">
        <p class="lp-help">The page whose client bundle will be scanned.</p>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpEndpoints" data-explain="lp.endpoints">Backend endpoints (optional, one per line)</label>
        <textarea id="lpEndpoints" placeholder="https://api.example.com/chat" spellcheck="false">${esc(defaultEndpoints)}</textarea>
        <p class="lp-help">GET-probed for echoed secrets, verbose errors and CORS exposure. Pre-filled with this site's AI backend when known.</p>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpSecrets" data-explain="lp.secrets">Secrets to track (optional, one per line)</label>
        <textarea id="lpSecrets" placeholder="Paste a specific key to hunt for, e.g. your Gemini key" spellcheck="false"></textarea>
        <p class="lp-help">Exact-match needles. Kept in memory only, masked in the report, never stored or sent anywhere but your own proxy to your own target. Generic AI keys (AIza…, sk-…, sk-ant-…) are detected automatically regardless.</p>
      </div>
      <div class="lp-bar">
        <button class="lp-btn" id="lpRun" disabled>Run exposure scan</button>
        <button class="lp-btn lp-ghost" id="lpRoutes" disabled title="Also probe a small safe wordlist of debug/config routes on the target and backend origins">Include debug-route probe</button>
      </div>
      <div class="lp-prog" id="lpProg" hidden></div>
    </div>

    <div id="lpOut"></div>
    <p class="lp-note">A "server-side only" result means no copy of the tracked secret was observed in anything the scanner could reach from the client or in any backend response it saw — not a proof of absolute safety. LEAKPROBE never calls a provider API and never spends a key to confirm it is live.</p>
  </div>`;

  const $ = (id) => main.querySelector(id);
  const consent = $("#lpConsent"), runBtn = $("#lpRun"), routeBtn = $("#lpRoutes");
  const prog = $("#lpProg"), out = $("#lpOut");
  consent.onchange = () => { runBtn.disabled = routeBtn.disabled = !consent.checked; };

  let busy = false;
  const log = (m) => { prog.hidden = false; prog.textContent += (prog.textContent ? "\n" : "") + m; prog.scrollTop = prog.scrollHeight; };

  async function run(withRoutes) {
    if (busy) return;
    const target = ($("#lpUrl").value || "").trim();
    if (!/^https?:\/\//i.test(target)) { toast("Enter a full target URL starting with http(s)://"); return; }
    const endpoints = ($("#lpEndpoints").value || "").split(/\n+/).map((s) => s.trim()).filter((s) => /^https?:\/\//i.test(s));
    const needles = ($("#lpSecrets").value || "").split(/\n+/).map((s) => s.trim()).filter((s) => s.length >= 8);

    busy = true; runBtn.disabled = routeBtn.disabled = true; prog.textContent = ""; out.innerHTML = "";
    runBtn.textContent = "Scanning…";
    const findings = [];    // all findings tagged with .where and .source
    const assetRows = [];   // {url, status, kind, n}
    const backendRows = []; // {url, status, cors, err, n}
    const routeHits = [];

    try {
      // ---- Phase A: static client-exposure ----
      log("Phase A — fetching the page: " + target);
      let doc;
      try { doc = await dnFetch(target, { raw: true, timeout: 20000, max: ASSET_MAX_BYTES }); }
      catch (e) { log("  ! could not fetch target: " + ((e && e.message) || e)); }
      const base = (doc && (doc.finalUrl || doc.url)) || target;
      let graph = { scripts: [], modules: [], styles: [], configs: [], sw: [], inline: [] };
      if (doc && doc.body) {
        // scan the document itself + inline scripts
        pushFindings(findings, scanBytes(doc.body, "client-asset", needles, { detectors: BUNDLE_DETECTORS }), base + " (document)");
        graph = assetGraph(doc.body, base);
        for (const inl of graph.inline) pushFindings(findings, scanBytes(inl.text, "client-asset", needles, { detectors: BUNDLE_DETECTORS }), base + " (inline script)");
      }
      // collect the asset URLs (same-origin + cross-origin), de-duped, capped
      const assetUrls = dedupe([
        ...graph.scripts, ...graph.modules, ...graph.styles,
        ...graph.configs.filter((c) => typeof c === "string"), ...graph.sw,
      ]).slice(0, MAX_ASSETS);
      log("Phase A — " + assetUrls.length + " asset(s) to fetch (cap " + MAX_ASSETS + ")");

      const fetched = new Set();
      const scanAsset = async (url) => {
        if (fetched.has(url)) return; fetched.add(url);
        let r;
        try { r = await dnFetch(url, { raw: true, timeout: 15000, max: ASSET_MAX_BYTES }); }
        catch (e) { assetRows.push({ url, status: "ERR", n: 0, note: (e && e.message) || "fetch failed" }); return; }
        const body = r.body || "";
        const before = findings.length;
        pushFindings(findings, scanBytes(body, "client-asset", needles, { detectors: BUNDLE_DETECTORS }), url);
        // follow a source map if present, and the conventional <url>.map
        const smRef = extractSourceMapUrl(body, url);
        const smUrl = smRef && smRef.url ? smRef.url : (/\.(?:js|mjs|css)$/i.test(url) ? url + ".map" : null);
        if (smUrl) {
          try {
            const sm = await dnFetch(smUrl, { raw: true, timeout: 12000, max: ASSET_MAX_BYTES });
            if (sm && sm.body && sm.body.trim().startsWith("{")) {
              const srcs = parseSourceMap(sm.body);
              for (const s of srcs) pushFindings(findings, scanBytes(s.content, "source-map", needles, { detectors: BUNDLE_DETECTORS }), smUrl + " ‹" + s.source + "›");
              if (srcs.length) log("  ↳ source map: " + srcs.length + " original source(s) in " + short(smUrl));
            }
          } catch (_) {}
        }
        assetRows.push({ url, status: r.status, n: findings.length - before });
      };
      await pool(assetUrls, MAX_CONCURRENCY, scanAsset);

      // ---- Phase C/B2: backend probing ----
      if (endpoints.length) log("Backend — probing " + endpoints.length + " endpoint(s)");
      for (const ep of endpoints) {
        let r;
        try { r = await dnFetch(ep, { raw: true, timeout: 15000 }); }
        catch (e) { backendRows.push({ url: ep, status: "ERR", note: (e && e.message) || "fetch failed" }); continue; }
        const body = r.body || "";
        const before = findings.length;
        // a GET to a POST-only API usually returns an error; scan it for echoed secrets/config
        pushFindings(findings, scanBytes(body, r.status >= 400 ? "backend-error" : "backend-response", needles, { detectors: BACKEND_DETECTORS }), ep);
        const cors = gradeCors(r.headers || {}, base);
        const err = gradeErrorLeak(body);
        backendRows.push({ url: ep, status: r.status, cors, err, n: findings.length - before });
      }

      // ---- optional debug-route probe ----
      if (withRoutes) {
        const origins = dedupe([originOf(target), ...endpoints.map(originOf)].filter(Boolean));
        const probes = [];
        for (const o of origins) for (const p of commonDebugRoutes()) probes.push(o + p);
        log("Routes — probing " + probes.length + " path(s) across " + origins.length + " origin(s)");
        await pool(probes.slice(0, 80), MAX_CONCURRENCY, async (u) => {
          let r;
          try { r = await dnFetch(u, { raw: true, timeout: 10000 }); } catch (_) { return; }
          const g = gradeRouteResponse(pathOf(u), r.status, r.body || "");
          if (g.hit) {
            routeHits.push({ url: u, status: r.status, severity: g.severity, detail: g.detail });
            pushFindings(findings, scanBytes(r.body || "", "debug-route", needles, { detectors: BACKEND_DETECTORS }), u);
          }
        });
      }

      log("Done. " + findings.length + " finding(s) across " + (assetRows.length) + " asset(s) and " + backendRows.length + " endpoint(s).");
      renderReport(out, { target, needles, findings, assetRows, backendRows, routeHits });
    } finally {
      busy = false; runBtn.textContent = "Run exposure scan"; runBtn.disabled = routeBtn.disabled = !consent.checked;
    }
  }

  runBtn.onclick = () => run(false);
  routeBtn.onclick = () => run(true);
}

/* ------------------------------------------------------------- rendering */

function renderReport(out, R) {
  const { target, needles, findings, assetRows, backendRows, routeHits } = R;
  const score = scoreExposure(findings);
  const secretFindings = findings.filter((f) => f.kind === "secret");

  // verdict per tracked needle (always show at least the overall)
  const verdicts = [];
  for (const n of needles) {
    const hits = findings.filter((f) => f.id === "owner-secret" && f.value === n);
    verdicts.push({ name: short(n, 10), v: classifyPlacement(hits), count: hits.length });
  }
  const onClient = (f) => f.where === "client-asset" || f.where === "source-map" || f.where === "client-request";
  // Unambiguous AI/model credentials — if these are client-side they are a real leak.
  const hardAiKeys = secretFindings.filter((f) => /^(openai-key|anthropic-key|google-oauth)$/.test(f.id));
  // Google API keys (AIza…) are ambiguous: usually the public Firebase Web config key.
  const googleKeys = secretFindings.filter((f) => f.id === "gcp-key");

  let html = "";

  // headline cards
  const gradeLvl = { critical: "critical", high: "high", elevated: "medium", low: "low", clean: "pass" }[score.grade] || "low";
  html += renderVerdict("Overall exposure", gradeLabel(score.grade), gradeReason(score), gradeLvl);

  // AI/model API keys (OpenAI / Anthropic / Google OAuth secret)
  const hardAiClient = hardAiKeys.filter(onClient);
  if (hardAiKeys.length) {
    const v = classifyPlacement(hardAiKeys);
    html += renderVerdict("AI / model API keys", v.label, hardAiKeys.length + " key value(s) observed (OpenAI / Anthropic / Google OAuth). " + v.reason, v.level);
  } else {
    html += renderVerdict("AI / model API keys", "None exposed", "No OpenAI (sk-…), Anthropic (sk-ant-…) or Google OAuth client secret was observed in the client bundle or any backend response.", "pass");
  }

  // Google API key (AIza…) — Firebase-vs-Gemini ambiguity
  if (googleKeys.length) {
    const client = googleKeys.filter(onClient).length;
    html += renderVerdict(
      "Google API key (AIza…)",
      client ? "In client bundle — review" : "Observed server-side",
      client
        ? (client + " Google API key(s) in the client bundle. If this is your Firebase Web config key it is expected and public — restrict it by HTTP referrer and enabled APIs in the Cloud console. If it is a Gemini / Generative Language key, it must move server-side and be rotated. Paste your exact Gemini key in “Secrets to track” to resolve this definitively.")
        : "A Google API key was seen only in a backend response, not the client bundle.",
      client ? "warning" : "pass",
    );
  }
  for (const vd of verdicts) html += renderVerdict("Tracked: " + vd.name, vd.v.label, vd.v.reason, vd.v.level);

  // KPIs
  html += `<div class="lp-kpis">
    ${kpi(score.secrets, "Secrets found")}
    ${kpi(secretFindings.filter((f) => f.where === "client-asset" || f.where === "source-map").length, "In client bundle")}
    ${kpi(secretFindings.filter((f) => f.where === "backend-response" || f.where === "backend-error").length, "In backend responses")}
    ${kpi(assetRows.length, "Assets scanned")}
    ${kpi(routeHits.length, "Debug-route hits")}
  </div>`;

  // client assets with findings
  html += `<h2>Client bundle</h2>`;
  const withF = assetRows.filter((a) => a.n > 0);
  if (!assetRows.length) html += `<div class="lp-empty">The target page could not be fetched.</div>`;
  else if (!withF.length) html += `<div class="lp-empty">No secrets found in ${assetRows.length} scanned asset(s). ${needles.length ? "None of the tracked secrets appear in the client bundle." : ""}</div>`;
  else html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Asset</th><th>HTTP</th><th>Findings</th></tr></thead><tbody>${
    withF.map((a) => `<tr><td><code>${esc(short(a.url, 70))}</code></td><td>${esc(String(a.status))}</td><td>${a.n}</td></tr>`).join("")}</tbody></table></div>`;

  // findings detail (secrets first)
  const evid = findings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity)).slice(0, 200);
  if (evid.length) {
    html += `<h2>Evidence (${findings.length} finding${findings.length === 1 ? "" : "s"}${findings.length > 200 ? ", showing 200" : ""})</h2>`;
    html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Severity</th><th>Type</th><th>Where</th><th>Value (masked)</th><th>Location</th></tr></thead><tbody>${
      evid.map((f) => `<tr><td>${pill(f.severity)}</td><td>${esc(f.label)}</td><td>${esc(whereLabel(f.where))}</td><td><code>${esc(f.masked || "")}</code></td><td><code>${esc(short(f.source || "", 48))}${f.line ? ":" + f.line : ""}</code></td></tr>`).join("")}</tbody></table></div>`;
  }

  // backend
  if (backendRows.length) {
    html += `<h2>Backend endpoints</h2>`;
    html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Endpoint</th><th>HTTP</th><th>CORS</th><th>Error hygiene</th><th>Secrets</th></tr></thead><tbody>${
      backendRows.map((b) => {
        if (b.status === "ERR") return `<tr><td><code>${esc(short(b.url, 60))}</code></td><td colspan="4">${esc(b.note || "error")}</td></tr>`;
        const corsCell = b.cors ? `${pill(b.cors.level)} ${esc(b.cors.label)}` : "—";
        const errCell = b.err && b.err.signals.length ? `${pill(b.err.level)} ${esc(b.err.signals.map((s) => s.detail).join("; "))}` : `${pill("pass")} clean`;
        return `<tr><td><code>${esc(short(b.url, 60))}</code></td><td>${esc(String(b.status))}</td><td>${corsCell}</td><td>${errCell}</td><td>${b.n || 0}</td></tr>`;
      }).join("")}</tbody></table></div>`;
  }

  // debug routes
  if (routeHits.length) {
    html += `<h2>Debug / config routes</h2>`;
    html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Severity</th><th>Route</th><th>HTTP</th><th>What leaked</th></tr></thead><tbody>${
      routeHits.map((r) => `<tr><td>${pill(r.severity)}</td><td><code>${esc(short(r.url, 70))}</code></td><td>${esc(String(r.status))}</td><td>${esc(r.detail || "")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  // export
  html += `<div class="lp-bar" style="margin-top:14px"><button class="lp-btn lp-ghost" id="lpExport">Export JSON</button></div>`;

  out.innerHTML = html;
  const ex = out.querySelector("#lpExport");
  if (ex) ex.onclick = () => {
    const report = {
      tool: "LEAKPROBE", target, generatedAt: new Date().toISOString(),
      overall: score,
      aiKeys: { hardCount: hardAiKeys.length, hardOnClient: hardAiClient.length, googleKeyCount: googleKeys.length, googleKeyOnClient: googleKeys.filter(onClient).length },
      trackedSecrets: verdicts.map((v) => ({ name: v.name, verdict: v.v.label, level: v.v.level, occurrences: v.count })),
      findings: findings.map((f) => ({ severity: f.severity, type: f.label, id: f.id, where: f.where, masked: f.masked, source: f.source, line: f.line || null })),
      backend: backendRows.map((b) => ({ url: b.url, status: b.status, cors: b.cors && b.cors.label, errorHygiene: b.err && b.err.level })),
      debugRoutes: routeHits,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = "leakprobe-report.json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    toast("Report exported");
  };
}

function renderVerdict(title, label, reason, level) {
  const lv = level || (/\b(critical|exposed|leaked)\b/i.test(label) ? "critical" : /\b(warning|reachable)\b/i.test(label) ? "warning" : "pass");
  const v = LV[lv] || LV.pass;
  return `<div class="lp-verdict"><div class="lp-vchip" style="background:${v.c}">${esc(v.t)}</div><div class="lp-vbody"><b>${esc(title)}: ${esc(label)}</b><span>${esc(reason)}</span></div></div>`;
}

/* --------------------------------------------------------------- helpers */

function pushFindings(bucket, list, source) { for (const f of list) bucket.push({ ...f, source }); }
function dedupe(a) { return [...new Set(a.filter(Boolean))]; }
function kpi(n, l) { return `<div class="lp-kpi"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`; }
function sevRank(s) { return { critical: 4, high: 3, medium: 2, low: 1 }[s] || 0; }
function short(s, n = 56) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }
function originOf(u) { try { return new URL(u).origin; } catch (_) { return null; } }
function pathOf(u) { try { const x = new URL(u); return x.pathname + x.search; } catch (_) { return u; } }
function whereLabel(w) {
  return { "client-asset": "Client bundle", "source-map": "Source map", "client-request": "Client request", "backend-response": "Backend response", "backend-error": "Backend error", "debug-route": "Debug route", "config-route": "Config route" }[w] || (w || "—");
}
function gradeLabel(g) { return { critical: "Critical exposure", high: "High exposure", elevated: "Elevated", low: "Low", clean: "No exposure found" }[g] || g; }
function gradeReason(score) {
  if (score.clientExposed) return "A secret was found in the client bundle — readable by anyone loading the site. Rotate it and move it server-side.";
  if (score.backendLeaked) return "A secret was returned by a backend response. Rotate it and stop the backend echoing it.";
  if (score.grade === "clean") return "No secrets were found in the scanned client assets or observed backend responses. This is not a proof of absolute safety.";
  if (score.clientAmbiguous) return "No unambiguous credential leak. A Google API key or api-key-shaped value is in the client bundle — commonly a public Firebase Web config key; review the card below and confirm it is not a Gemini key.";
  return score.secrets + " secret-shaped value(s) and " + (score.total - score.secrets) + " other finding(s). Review the evidence below.";
}

export default renderLeakprobe;
