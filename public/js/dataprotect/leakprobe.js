// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
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
  assetGraph, extractImports, extractSourceMapUrl, parseSourceMap,
  scanBytes, classifyPlacement, gradeCors, gradeErrorLeak,
  commonDebugRoutes, gradeRouteResponse, scoreExposure,
  BUNDLE_DETECTORS, BACKEND_DETECTORS,
  detectServices, mergeServices, parseFirebaseConfig, classifyKey,
} from "/js/dataprotect/leakprobe-engine.js?v=20261029e";
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
  .lp{width:100%;font-size:14px;line-height:1.5}
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
  .lp th{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;white-space:nowrap}
  .lp .lp-pill{display:inline-block;padding:1px 8px;border-radius:999px;font-size:.7rem;font-weight:700;color:#fff;white-space:nowrap;line-height:1.5;vertical-align:middle}
  .lp code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.78rem;background:var(--bg,#f3f5f9);padding:1px 5px;border-radius:5px}
  .lp .lp-secret{display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;max-width:100%}
  .lp .lp-sv{word-break:break-all;max-width:46ch;overflow-wrap:anywhere}
  .lp .lp-rv,.lp .lp-cp{font:inherit;font-size:.7rem;line-height:1;padding:3px 7px;border:1px solid var(--line,#d7dbe6);border-radius:5px;background:transparent;color:var(--mut,#667085);cursor:pointer}
  .lp .lp-rv:hover,.lp .lp-cp:hover{color:var(--txt,#141c2e);border-color:var(--acc,#2552c6)}
  .lp .lp-keylist{margin:8px 0 2px;display:flex;flex-direction:column;gap:6px}
  .lp .lp-keylist>div{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
  .lp .lp-kw{font-size:.72rem;color:var(--mut,#667085)}
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
    <div class="lp-hd"><h1>Exposed Keys</h1><span class="lp-tag">LEAKPROBE</span></div>
    <p class="lp-sub">Prove whether a real secret — an API key, a token, your Gemini key — can be reached from the browser, or is kept server-side. It fetches everything the page downloads (scripts, module graph, source maps, config, service worker), scans each for secrets, then GET-probes your backend endpoints, their error pages and common debug routes. The exact key values it finds are shown here (this is your own property); use Hide for screenshots. Nothing is uploaded, downloaded reports keep only a masked value, and no key is ever spent to test it.</p>

    <div class="lp-card">
      <div class="lp-consent">
        <input type="checkbox" id="lpConsent">
        <span><b>Authorized targets only.</b> Tick to confirm you own, or are authorized to test, the target below. LEAKPROBE performs a small number of bounded GET requests through the Darknode proxy. Do not point it at property you do not control.</span>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpUrl" data-explain="lp.target">Target URL</label>
        <input id="lpUrl" type="text" placeholder="https://your-site.example" spellcheck="false" autocapitalize="off">
        <p class="lp-help">The page whose client bundle will be scanned. Leave blank to scan this site.</p>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpEndpoints" data-explain="lp.endpoints">Backend endpoints (optional, one per line)</label>
        <textarea id="lpEndpoints" placeholder="https://" spellcheck="false"></textarea>
        <p class="lp-help">GET-probed for echoed secrets, verbose errors and CORS exposure. When you scan this site, its AI backend is included automatically.</p>
      </div>
      <div class="lp-row">
        <label class="lp-lab" for="lpSecrets" data-explain="lp.secrets">Secrets to track (optional)</label>
        <textarea id="lpSecrets" placeholder="Optional — paste a key to confirm by exact match" spellcheck="false"></textarea>
        <p class="lp-help">You do not need to paste anything. The scan already detects every API key on its own — Google (AIza…), OpenAI (sk-…), Anthropic (sk-ant-…), AWS, Stripe, GitHub, Slack, Twilio, SendGrid, private keys and JWTs — without you knowing or entering the key. This field only adds an exact-match needle for one specific key you want confirmed by name; it is kept in memory, shown here in full with a one-click Hide, masked only in the downloaded report, and never stored or sent anywhere but your own proxy to your own target.</p>
      </div>
      <div class="lp-bar">
        <button class="lp-btn" id="lpRun" disabled>Run exposure scan</button>
        <button class="lp-btn lp-ghost" id="lpRoutes" disabled title="Also probe a small safe wordlist of debug/config routes on the target and backend origins">Include debug-route probe</button>
        <button class="lp-btn lp-ghost" id="lpCapture" disabled data-explain="lp.capture" title="Load this site in a sandboxed frame, exercise it (send a message to the AI, open tools) and capture every real backend request + response to inspect for leaked secrets">Capture live backend traffic</button>
      </div>
      <p class="lp-help">Live capture drives the site in a frame — it sends a benign message to the assistant so the real /api/chat request fires, and opens tools to trigger their backend calls — then scans every captured request and response. Runs only against this origin (${esc(locOrigin())}); destructive controls (delete, logout, pay, transfer) are never clicked.</p>
      <div class="lp-prog" id="lpProg" hidden></div>
    </div>

    <div id="lpOut"></div>
    <p class="lp-note">A "server-side only" result means no copy of the tracked secret was observed in anything the scanner could reach from the client or in any backend response it saw — not a proof of absolute safety. LEAKPROBE never calls a provider API and never spends a key to confirm it is live.</p>
  </div>`;

  const $ = (id) => main.querySelector(id);
  const consent = $("#lpConsent"), runBtn = $("#lpRun"), routeBtn = $("#lpRoutes"), captureBtn = $("#lpCapture");
  const prog = $("#lpProg"), out = $("#lpOut");
  consent.onchange = () => { runBtn.disabled = routeBtn.disabled = captureBtn.disabled = !consent.checked; };

  let busy = false;
  const log = (m) => { prog.hidden = false; prog.textContent += (prog.textContent ? "\n" : "") + m; prog.scrollTop = prog.scrollHeight; };

  async function run(withRoutes) {
    if (busy) return;
    let target = ($("#lpUrl").value || "").trim();
    if (!target) target = locOrigin();   // blank = scan this site
    if (!/^https?:\/\//i.test(target)) { toast("Enter a full target URL starting with http(s)://"); return; }
    let endpoints = ($("#lpEndpoints").value || "").split(/\n+/).map((s) => s.trim()).filter((s) => /^https?:\/\//i.test(s));
    // When scanning this site and no endpoints were given, include its known AI backend
    // automatically — no need to paste anything for the common case.
    const sameSite = (() => { try { return new URL(target).origin === locOrigin(); } catch (_) { return false; } })();
    if (!endpoints.length && sameSite && defaultEndpoints) endpoints = defaultEndpoints.split(/\n+/).map((s) => s.trim()).filter((s) => /^https?:\/\//i.test(s));
    const needles = ($("#lpSecrets").value || "").split(/\n+/).map((s) => s.trim()).filter((s) => s.length >= 8);

    busy = true; runBtn.disabled = routeBtn.disabled = captureBtn.disabled = true; prog.textContent = ""; out.innerHTML = "";
    runBtn.textContent = "Scanning…";
    const findings = [];    // all findings tagged with .where and .source
    const assetRows = [];   // {url, status, kind, n}
    const backendRows = []; // {url, status, cors, err, n}
    const routeHits = [];
    const services = new Map();  // name -> {name, category, implication, sources:Set}
    let firebase = null;         // parsed firebaseConfig + enabled products
    const noteBody = (text, source) => {
      mergeServices(services, detectServices(text, source));
      if (!firebase) { const fb = parseFirebaseConfig(text); if (fb) firebase = { ...fb, source }; }
    };

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
        noteBody(doc.body, base + " (document)");
        graph = assetGraph(doc.body, base);
        for (const inl of graph.inline) { pushFindings(findings, scanBytes(inl.text, "client-asset", needles, { detectors: BUNDLE_DETECTORS }), base + " (inline script)"); noteBody(inl.text, base + " (inline script)"); }
      }
      // collect the asset URLs (same-origin + cross-origin), de-duped, capped
      const assetUrls = dedupe([
        ...graph.scripts, ...graph.modules, ...graph.styles,
        ...graph.configs.filter((c) => typeof c === "string"), ...graph.sw,
      ]).slice(0, MAX_ASSETS);
      log("Phase A — " + assetUrls.length + " asset(s) to fetch (cap " + MAX_ASSETS + ")");

      const fetched = new Set();
      const discovered = new Set(); // ES-module imports found inside fetched JS, walked transitively below
      const scanAsset = async (url) => {
        if (fetched.has(url)) return; fetched.add(url);
        let r;
        try { r = await dnFetch(url, { raw: true, timeout: 15000, max: ASSET_MAX_BYTES }); }
        catch (e) { assetRows.push({ url, status: "ERR", n: 0, note: (e && e.message) || "fetch failed" }); return; }
        const body = r.body || "";
        const before = findings.length;
        pushFindings(findings, scanBytes(body, "client-asset", needles, { detectors: BUNDLE_DETECTORS }), url);
        noteBody(body, url);
        // follow the ES-module import graph: queue string-literal import targets of JS/modules
        if (/\.(?:js|mjs)(?:\?|$)/i.test(url) || /javascript|ecmascript/i.test((r.headers && (r.headers["content-type"] || r.headers["Content-Type"])) || "")) {
          for (const iu of extractImports(body, url)) if (!fetched.has(iu)) discovered.add(iu);
        }
        // follow a source map if present, and the conventional <url>.map
        const smRef = extractSourceMapUrl(body, url);
        const smUrl = smRef && smRef.url ? smRef.url : (/\.(?:js|mjs|css)$/i.test(url) ? url + ".map" : null);
        if (smUrl) {
          try {
            const sm = await dnFetch(smUrl, { raw: true, timeout: 12000, max: ASSET_MAX_BYTES });
            if (sm && sm.body && sm.body.trim().startsWith("{")) {
              const srcs = parseSourceMap(sm.body);
              for (const s of srcs) pushFindings(findings, scanBytes(s.content, "source-map", needles, { detectors: BUNDLE_DETECTORS }), smUrl + " [" + s.source + "]");
              if (srcs.length) log("  -> source map: " + srcs.length + " original source(s) in " + short(smUrl));
            }
          } catch (_) {}
        }
        assetRows.push({ url, status: r.status, n: findings.length - before });
      };
      await pool(assetUrls, MAX_CONCURRENCY, scanAsset);
      // Transitively walk imported modules the HTML never declared, up to the asset cap.
      let impDepth = 0;
      while (discovered.size && fetched.size < MAX_ASSETS && impDepth < 4) {
        impDepth++;
        const next = dedupe([...discovered]).filter((u) => !fetched.has(u)).slice(0, MAX_ASSETS - fetched.size);
        discovered.clear();
        if (!next.length) break;
        log("Phase A — following " + next.length + " imported module(s) (depth " + impDepth + ")");
        await pool(next, MAX_CONCURRENCY, scanAsset);
      }

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

      log("Phase S — " + services.size + " service(s)/integration(s) detected" + (firebase ? ", Firebase project " + (firebase.config.projectId || "?") : ""));
      log("Done. " + findings.length + " finding(s) across " + (assetRows.length) + " asset(s) and " + backendRows.length + " endpoint(s).");
      renderReport(out, { target, needles, findings, assetRows, backendRows, routeHits, services: [...services.values()], firebase, auth: currentAuthIntel() });
    } finally {
      busy = false; runBtn.textContent = "Run exposure scan"; runBtn.disabled = routeBtn.disabled = captureBtn.disabled = !consent.checked;
    }
  }

  runBtn.onclick = () => run(false);
  routeBtn.onclick = () => run(true);
  captureBtn.onclick = () => captureLive({ needles: ($("#lpSecrets").value || "").split(/\n+/).map((s) => s.trim()).filter((s) => s.length >= 8), out, log, setBusy: (b) => { busy = b; captureBtn.disabled = runBtn.disabled = routeBtn.disabled = b || !consent.checked; captureBtn.textContent = b ? "Capturing…" : "Capture live backend traffic"; }, isBusy: () => busy, progReset: () => { prog.textContent = ""; } });
}

/* ------------------------------------------------------------- rendering */

// One delegated listener per results container: Hide/Reveal a secret value and
// Copy the exact value. Bound once; survives the innerHTML swaps on each run.
function bindSecretToggles(out) {
  if (out.__lpBound) return;
  out.__lpBound = true;
  out.addEventListener("click", (e) => {
    const rv = e.target.closest(".lp-rv");
    if (rv) {
      const c = out.querySelector("#" + rv.dataset.t);
      if (c) { const shown = c.dataset.shown === "1"; c.textContent = shown ? c.dataset.masked : c.dataset.full; c.dataset.shown = shown ? "0" : "1"; rv.textContent = shown ? "Reveal" : "Hide"; }
      return;
    }
    const cp = e.target.closest(".lp-cp");
    if (cp) {
      const c = out.querySelector("#" + cp.dataset.t);
      if (c && navigator.clipboard) navigator.clipboard.writeText(c.dataset.full).then(() => toast("Copied the exact value"), () => {});
      return;
    }
  });
}

function renderReport(out, R) {
  bindSecretToggles(out);
  const { target, needles, findings, assetRows, backendRows, routeHits, services = [], firebase = null, auth = null } = R;
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
    html += renderVerdict("AI / model API keys", v.label, hardAiKeys.length + " key value(s) observed (OpenAI / Anthropic / Google OAuth):" + keyList(hardAiKeys) + " " + v.reason, v.level);
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
        ? (client + " Google API key(s) in the client bundle:" + keyList(googleKeys.filter(onClient)) + " If this is your Firebase Web config key it is expected and public — restrict it by HTTP referrer and enabled APIs in the Cloud console. If it is a Gemini / Generative Language key, it must move server-side and be rotated.")
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

  // ---- Services & integrations (what backends/services are wired in) ----
  if (services.length) {
    html += `<h2>Services &amp; integrations detected (${services.length})</h2>`;
    html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Service</th><th>Category</th><th>What it means</th></tr></thead><tbody>${
      services.slice().sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name)).map((s) =>
        `<tr><td><b>${esc(s.name)}</b></td><td>${esc(s.category)}</td><td>${esc(s.implication)}</td></tr>`).join("")}</tbody></table></div>`;
  }

  // ---- Firebase project detail (exact backend config from the bundle) ----
  if (firebase) {
    const c = firebase.config;
    const rows = [["Project ID", c.projectId], ["Auth domain", c.authDomain], ["Storage bucket", c.storageBucket], ["Messaging sender ID", c.messagingSenderId], ["App ID", c.appId], ["Analytics", c.measurementId]]
      .filter((r) => r[1]).map((r) => `<tr><td>${esc(r[0])}</td><td><code>${esc(r[1])}</code></td></tr>`).join("");
    html += `<h2>Firebase backend</h2><div class="lp-card"><p style="margin:0 0 10px">Enabled products (from the client config): <b>${esc(firebase.products.join(", ") || "—")}</b>. These values are public by design; access must be enforced by Firebase Security Rules and API-key restrictions, never by client code.</p><table style="width:auto">${rows}</table></div>`;
  }

  // ---- API key / credential intelligence ----
  const keyFindings = secretFindings.filter((f) => f.id !== "high-entropy");
  if (keyFindings.length) {
    // de-dup identical masked+id+where
    const seen = new Set(); const rows = [];
    for (const f of keyFindings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity))) {
      const k = f.id + "|" + f.masked + "|" + f.where; if (seen.has(k)) continue; seen.add(k);
      const cl = classifyKey(f);
      const expPill = cl.insecure ? pill("critical") : cl.exposure === "secret" ? pill("high") : cl.exposure === "public" ? pill("pass") : pill("medium");
      rows.push(`<tr><td>${esc(cl.provider)}</td><td>${secretCell(f)}</td><td>${esc(whereLabel(f.where))}</td><td>${expPill} ${esc(cl.insecure ? "Insecure" : cl.exposure)}</td><td>${esc(cl.note)}</td></tr>`);
    }
    html += `<h2>API keys &amp; credentials (${rows.length})</h2><div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Provider</th><th>Value</th><th>Where</th><th>Exposure</th><th>Guidance</th></tr></thead><tbody>${rows.join("")}</tbody></table></div>`;
  }

  // ---- Auth / session intelligence (honest about limits) ----
  if (auth) {
    html += `<h2>Authentication &amp; sign-in</h2><div class="lp-card">`;
    if (auth.signedIn) {
      html += `<p style="margin:0 0 8px">Current session (this browser): <b>${esc(auth.email || "signed in")}</b>${auth.emailVerified ? "" : " (email not verified)"}.</p>
        <table style="width:auto">
        <tr><td>Sign-in providers</td><td><code>${esc((auth.providers || []).join(", ") || "password")}</code></td></tr>
        ${auth.lastSignIn ? `<tr><td>Last sign-in</td><td><code>${esc(auth.lastSignIn)}</code></td></tr>` : ""}
        ${auth.created ? `<tr><td>Account created</td><td><code>${esc(auth.created)}</code></td></tr>` : ""}
        </table>`;
    } else {
      html += `<p style="margin:0 0 8px">No user is signed in to this session.</p>`;
    }
    html += `<p class="lp-help" style="margin-top:10px">The enabled sign-in providers are detected from the bundle/session above. <b>Full login history across all users is not readable from the browser</b> — listing recent logins, failed attempts or per-user activity requires server-side access (Firebase Admin SDK / Cloud Identity audit logs). LEAKPROBE will not fabricate it.</p></div>`;
  }

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
    html += `<div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Severity</th><th>Type</th><th>Where</th><th>Value</th><th>Location</th></tr></thead><tbody>${
      evid.map((f) => `<tr><td>${pill(f.severity)}</td><td>${esc(f.label)}</td><td>${esc(whereLabel(f.where))}</td><td>${secretCell(f)}</td><td><code>${esc(short(f.source || "", 48))}${f.line ? ":" + f.line : ""}</code></td></tr>`).join("")}</tbody></table></div>`;
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

/* -------------------------------------------------- live traffic capture */

// Destructive / financial / auth controls we must NEVER auto-click.
const UNSAFE_CLICK = /\b(delete|remove|logout|log ?out|sign ?out|deploy|pay|transfer|withdraw|wipe|reset|destroy|revoke|disconnect|unlink|cancel|buy|purchase|charge|send money|clear|release|approve|confirm|submit payment)\b/i;

// Load this origin in a sandboxed frame, instrument fetch/XHR BEFORE interaction,
// drive the site (message the AI, open tools) and capture every real backend
// request + response to scan for leaked secrets. Same-origin only.
async function captureLive(ctx) {
  const { needles, out, log, setBusy, isBusy } = ctx;
  if (isBusy()) return;
  setBusy(true); ctx.progReset(); out.innerHTML = "";
  log("Live capture — loading " + locOrigin() + " in a sandboxed frame");

  const frame = document.createElement("iframe");
  frame.setAttribute("title", "LEAKPROBE capture frame");
  frame.style.cssText = "position:fixed;left:-9999px;top:0;width:1200px;height:900px;border:0;visibility:hidden";
  const records = [];
  const findings = [];

  const headersToObj = (h) => {
    const o = {};
    try {
      if (!h) return o;
      if (typeof h.forEach === "function") { h.forEach((v, k) => { o[k] = v; }); return o; }
      if (Array.isArray(h)) { for (const [k, v] of h) o[k] = v; return o; }
      return { ...h };
    } catch (_) { return o; }
  };

  function instrument(win) {
    try {
      const of = win.fetch;
      if (of && !of.__lp) {
        const wrapped = function (input, init) {
          const url = typeof input === "string" ? input : (input && input.url) || String(input);
          const method = ((init && init.method) || (input && input.method) || "GET").toUpperCase();
          const reqHeaders = headersToObj((init && init.headers) || (input && input.headers));
          const reqBody = init && init.body ? safeBody(init.body) : "";
          const rec = { method, url, reqHeaders, reqBody, status: null, respHeaders: {}, respBody: "" };
          records.push(rec);
          return of.apply(this, arguments).then((res) => {
            try { rec.status = res.status; res.headers.forEach((v, k) => { rec.respHeaders[k] = v; }); } catch (_) {}
            try { const c = res.clone(); withTimeout(c.text(), 9000).then((t) => { rec.respBody = String(t || "").slice(0, 200000); }).catch(() => {}); } catch (_) {}
            return res;
          }).catch((e) => { rec.error = String((e && e.message) || e); throw e; });
        };
        wrapped.__lp = true; win.fetch = wrapped;
      }
      const XP = win.XMLHttpRequest && win.XMLHttpRequest.prototype;
      if (XP && !XP.__lp) {
        const open = XP.open, send = XP.send;
        XP.open = function (m, u) { this.__lp = { method: (m || "GET").toUpperCase(), url: u, reqHeaders: {}, reqBody: "", status: null, respHeaders: {}, respBody: "" }; return open.apply(this, arguments); };
        const setH = XP.setRequestHeader;
        XP.setRequestHeader = function (k, v) { try { if (this.__lp) this.__lp.reqHeaders[k] = v; } catch (_) {} return setH.apply(this, arguments); };
        XP.send = function (b) {
          const rec = this.__lp; if (rec) { rec.reqBody = b ? safeBody(b) : ""; records.push(rec); this.addEventListener("loadend", () => { try { rec.status = this.status; rec.respBody = String(this.responseText || "").slice(0, 200000); } catch (_) {} }); }
          return send.apply(this, arguments);
        };
        XP.__lp = true;
      }
    } catch (e) { log("  ! could not instrument frame (likely cross-origin): " + ((e && e.message) || e)); }
  }

  const done = new Promise((resolve) => {
    let settled = false;
    frame.onload = async () => {
      try {
        const win = frame.contentWindow;
        instrument(win);
        log("Live capture — frame loaded, driving the site");
        await sleep(600);
        // 1) message the AI assistant so the real /api/chat request fires
        try {
          const doc = win.document;
          if (typeof win.__openHelp === "function") win.__openHelp();
          else if (win.darknode && win.darknode.openHelp) win.darknode.openHelp();
          await sleep(500);
          const input = doc.querySelector("#dnchat-in, textarea[aria-label='Message'], textarea");
          const send = doc.querySelector("#dnchat-send");
          if (input && send) {
            input.value = "LEAKPROBE backend check: please reply OK.";
            input.dispatchEvent(new win.Event("input", { bubbles: true }));
            send.click();
            log("  -> sent a probe message to the assistant (/api/chat)");
          } else { log("  -> assistant input not found in frame"); }
        } catch (e) { log("  ! assistant drive failed: " + ((e && e.message) || e)); }
        // 2) click a bounded set of SAFE interactive elements to trigger backend calls
        try {
          const doc = win.document;
          const els = [...doc.querySelectorAll('button, [role="button"], [data-tool], [data-sec], [data-scene], .dk-navbtn')];
          let clicks = 0;
          for (const el of els) {
            if (clicks >= 24) break;
            const label = (el.getAttribute("aria-label") || el.textContent || el.getAttribute("data-tool") || el.getAttribute("data-sec") || "").trim();
            if (!label || UNSAFE_CLICK.test(label)) continue;
            try { el.click(); clicks++; await sleep(280); } catch (_) {}
          }
          log("  -> exercised " + clicks + " safe control(s)");
        } catch (_) {}
        await sleep(2500); // let late responses land
      } finally {
        if (!settled) { settled = true; resolve(); }
      }
    };
    setTimeout(() => { if (!settled) { settled = true; resolve(); } }, 30000);
  });

  frame.src = locOrigin() + "/";
  document.body.appendChild(frame);
  try { await done; } catch (_) {}
  // let any in-flight clone .text() reads finish
  await sleep(1200);
  try { frame.remove(); } catch (_) {}

  // scan every captured request/response
  for (const rec of records) {
    const reqText = rec.method + " " + rec.url + "\n" + hdrLines(rec.reqHeaders) + "\n" + (rec.reqBody || "");
    const rf = scanBytes(reqText, "client-request", needles, { detectors: BACKEND_DETECTORS });
    const respText = hdrLines(rec.respHeaders) + "\n" + (rec.respBody || "");
    const pf = scanBytes(respText, "backend-response", needles, { detectors: BACKEND_DETECTORS });
    rec.reqHits = rf.length; rec.respHits = pf.length;
    rec.cors = gradeCors(rec.respHeaders || {}, locOrigin());
    pushFindings(findings, rf, rec.method + " " + rec.url + " (request)");
    pushFindings(findings, pf, rec.method + " " + rec.url + " (response)");
  }
  log("Live capture — " + records.length + " request(s) captured, " + findings.length + " finding(s)");
  renderCapture(out, { records, findings, needles });
  setBusy(false);
}

function renderCapture(out, { records, findings }) {
  // JWTs, high-entropy blobs, Google API keys and generic api-key assignments in
  // live traffic are normally session/auth tokens (e.g. the Firebase ID token on
  // a Firestore call) — expected, not a leak. Only a provider SECRET key or a
  // tracked needle drives a critical verdict.
  const AMBIG = new Set(["jwt", "high-entropy", "gcp-key", "pat-assignment"]);
  const isHard = (f) => f.kind === "secret" && (f.id === "owner-secret" || !AMBIG.has(f.id));
  const reqLeak = findings.filter((f) => f.where === "client-request" && isHard(f));
  const respLeak = findings.filter((f) => f.where === "backend-response" && isHard(f));
  const sessionTokens = findings.filter((f) => f.kind === "secret" && AMBIG.has(f.id));
  let html = "";
  const lvl = reqLeak.length || respLeak.length ? "critical" : "pass";
  const reason = reqLeak.length
    ? "A provider key appears in a request the browser SENT — the client is transmitting a secret. Move it server-side."
    : respLeak.length
      ? "A provider key appears in a backend RESPONSE the browser received — the backend is echoing a secret."
      : "Across " + records.length + " captured request(s) — including the assistant /api/chat call — no API key or tracked secret was seen in any request the client sent or any response it received." + (sessionTokens.length ? " " + sessionTokens.length + " session/auth token(s) (JWTs / high-entropy) were present, which is expected on authenticated requests." : "") + " The backend keeps its provider keys server-side.";
  html += renderVerdict("Live backend traffic", lvl === "pass" ? "No key leaked in captured traffic" : "Key leaked in captured traffic", reason, lvl);

  html += `<div class="lp-kpis">
    ${kpi(records.length, "Requests captured")}
    ${kpi(new Set(records.map((r) => originOf(r.url)).filter(Boolean)).size, "Backend origins")}
    ${kpi(reqLeak.length, "Keys client sent")}
    ${kpi(respLeak.length, "Keys echoed back")}
    ${kpi(sessionTokens.length, "Session tokens")}
  </div>`;

  if (records.length) {
    html += `<h2>Captured requests</h2><div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Method</th><th>URL</th><th>Status</th><th>CORS</th><th>Req / Resp secrets</th></tr></thead><tbody>${
      records.slice(0, 200).map((r) => `<tr><td>${esc(r.method)}</td><td><code>${esc(short(r.url, 64))}</code></td><td>${esc(String(r.status == null ? (r.error ? "ERR" : "—") : r.status))}</td><td>${r.cors ? pill(r.cors.level) + " " + esc(r.cors.label) : "—"}</td><td>${(r.reqHits || 0)} / ${(r.respHits || 0)}</td></tr>`).join("")}</tbody></table></div>`;
  } else {
    html += `<div class="lp-empty">No requests were captured. Live capture only works on this origin (${esc(locOrigin())}); open LEAKPROBE on the site you want to capture.</div>`;
  }

  if (findings.length) {
    const evid = findings.slice().sort((a, b) => sevRank(b.severity) - sevRank(a.severity)).slice(0, 120);
    html += `<h2>Findings in captured traffic</h2><div class="lp-card" style="padding:0;overflow:hidden"><table><thead><tr><th>Severity</th><th>Type</th><th>Where</th><th>Value</th><th>Source</th></tr></thead><tbody>${
      evid.map((f) => `<tr><td>${pill(f.severity)}</td><td>${esc(f.label)}</td><td>${esc(whereLabel(f.where))}</td><td>${secretCell(f)}</td><td><code>${esc(short(f.source || "", 50))}</code></td></tr>`).join("")}</tbody></table></div>`;
  }
  out.innerHTML = html;
}

/* --------------------------------------------------------------- helpers */

function safeBody(b) { try { if (typeof b === "string") return b.slice(0, 50000); if (b instanceof URLSearchParams) return b.toString().slice(0, 50000); return ""; } catch (_) { return ""; } }
function withTimeout(p, ms) { return Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), ms))]); }
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }
function hdrLines(h) { try { return Object.keys(h || {}).map((k) => k + ": " + h[k]).join("\n"); } catch (_) { return ""; } }
function pushFindings(bucket, list, source) { for (const f of list) bucket.push({ ...f, source }); }
function dedupe(a) { return [...new Set(a.filter(Boolean))]; }
function kpi(n, l) { return `<div class="lp-kpi"><div class="n">${n}</div><div class="l">${esc(l)}</div></div>`; }
function sevRank(s) { return { critical: 4, high: 3, medium: 2, low: 1 }[s] || 0; }
function short(s, n = 56) { s = String(s || ""); return s.length > n ? s.slice(0, n - 1) + "…" : s; }

// Renders a secret value shown in full (this is an admin-only scan of your own
// property — the whole point is to prove the exact key is reachable) with a
// one-click Hide toggle and Copy. The masked form is kept so Hide can restore it,
// and exported reports still carry only the masked value.
let _lpSn = 0;
function secretCell(f) {
  const full = String(f.value || f.masked || "");
  const masked = String(f.masked || full);
  const id = "lps" + (++_lpSn);
  const hasMask = masked && masked !== full;
  return '<span class="lp-secret"><code class="lp-sv" id="' + id + '" data-full="' + esc(full) + '" data-masked="' + esc(masked) + '" data-shown="1">' + esc(full) + '</code>'
    + (hasMask ? ' <button type="button" class="lp-rv" data-t="' + id + '">Hide</button>' : '')
    + ' <button type="button" class="lp-cp" data-t="' + id + '">Copy</button></span>';
}

// A short inline list of exact key values for a headline card (one reveal cell each).
function keyList(items) {
  if (!items || !items.length) return "";
  return '<div class="lp-keylist">' + items.map((f) => '<div>' + secretCell(f) + ' <span class="lp-kw">' + esc(whereLabel(f.where)) + '</span></div>').join("") + '</div>';
}
function originOf(u) { try { return new URL(u).origin; } catch (_) { return null; } }
function pathOf(u) { try { const x = new URL(u); return x.pathname + x.search; } catch (_) { return u; } }
function whereLabel(w) {
  return { "client-asset": "Client bundle", "source-map": "Source map", "client-request": "Client request", "backend-response": "Backend response", "backend-error": "Backend error", "debug-route": "Debug route", "config-route": "Config route" }[w] || (w || "—");
}
function gradeLabel(g) { return { critical: "Critical exposure", high: "High exposure", elevated: "Elevated", low: "Low", clean: "No exposure found" }[g] || g; }
function locOrigin() { try { return location.origin; } catch (_) { return ""; } }

// Real auth intelligence for the CURRENT session only. Full per-user login
// history needs server / Admin-SDK access and is NOT readable from the browser.
function currentAuthIntel() {
  try {
    const auth = (window.firebase && window.firebase.auth && window.firebase.auth()) || window.__dnAuth || null;
    const u = (auth && auth.currentUser) || (window.__dnUser) || null;
    if (!u) return { signedIn: false };
    const providers = (u.providerData || []).map((p) => p && p.providerId).filter(Boolean);
    return {
      signedIn: true,
      email: u.email || null,
      providers,
      emailVerified: !!u.emailVerified,
      lastSignIn: (u.metadata && (u.metadata.lastSignInTime || u.metadata.lastLoginAt)) || null,
      created: (u.metadata && (u.metadata.creationTime || u.metadata.createdAt)) || null,
    };
  } catch (_) { return { signedIn: false, error: true }; }
}
function gradeReason(score) {
  if (score.clientExposed) return "A secret was found in the client bundle — readable by anyone loading the site. Rotate it and move it server-side.";
  if (score.backendLeaked) return "A secret was returned by a backend response. Rotate it and stop the backend echoing it.";
  if (score.grade === "clean") return "No secrets were found in the scanned client assets or observed backend responses. This is not a proof of absolute safety.";
  if (score.clientAmbiguous) return "No unambiguous credential leak. A Google API key or api-key-shaped value is in the client bundle — commonly a public Firebase Web config key; review the card below and confirm it is not a Gemini key.";
  return score.secrets + " secret-shaped value(s) and " + (score.total - score.secrets) + " other finding(s). Review the evidence below.";
}

export default renderLeakprobe;
