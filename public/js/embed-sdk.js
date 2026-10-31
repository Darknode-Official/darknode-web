// Embed SDK — generate iframe markup that shows one Darknode tool in embed mode on a Darknode-origin page.
// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Darknode runs any route in EMBED MODE with ?embed=1 — the full app boots but all chrome
// (sidebar, bootscreen, header, footer) is stripped, leaving just the one tool, so it can be
// iframed into another site. Framing is same-origin only (X-Frame-Options: SAMEORIGIN), and a
// signed-in Firebase session is inherited by same-origin iframes. This tool builds the markup.

import { NAV } from "/js/console-nav.js?v=20261029d";

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Secs that are not sensible to embed on a third-party page.
const EXCLUDE = new Set(["home", "settings", "admin", "docs", "downloads", "dlguide"]);

// Flatten the nav manifest into a flat, searchable list of embeddable tools.
function embeddableTools() {
  const out = [];
  const seen = new Set();
  (Array.isArray(NAV) ? NAV : []).forEach((g) => {
    (g.items || []).forEach((i) => {
      if (!i || !i.sec || EXCLUDE.has(i.sec) || seen.has(i.sec)) return;
      seen.add(i.sec);
      out.push({ sec: i.sec, label: i.label || i.sec, group: g.name || "" });
    });
  });
  out.sort((a, b) => a.label.localeCompare(b.label));
  return out;
}

const toast = (msg) => { try { if (typeof window.showToast === "function") window.showToast(msg); } catch (_) {} };

const EM_CSS =
  '<style>' +
  '.em-wrap{color:var(--txt);max-width:none}' +
  '.em-grid{display:grid;grid-template-columns:minmax(320px,1fr) minmax(320px,1.2fr);gap:16px;align-items:start}' +
  '@media(max-width:860px){.em-grid{grid-template-columns:1fr}}' +
  '.em-field{margin:0 0 14px}' +
  '.em-field:last-child{margin-bottom:0}' +
  '.em-label{display:block;font-size:.75rem;font-weight:600;color:var(--mut);margin:0 0 6px}' +
  '.em-input,.em-select{width:100%;box-sizing:border-box;background:var(--card2);border:1px solid var(--line);color:var(--txt);border-radius:6px;padding:9px 11px;font-size:.86rem;font-family:inherit}' +
  '.em-input:focus,.em-select:focus{outline:none;border-color:var(--acc);box-shadow:0 0 0 3px color-mix(in srgb,var(--acc) 15%,transparent)}' +
  '.em-row{display:flex;gap:12px;flex-wrap:wrap}' +
  '.em-row .em-field{flex:1;min-width:130px}' +
  '.em-tools{max-height:260px;overflow-y:auto;border:1px solid var(--line);border-radius:6px;background:var(--card2);margin-top:8px}' +
  '.em-tool{display:flex;justify-content:space-between;align-items:center;gap:10px;padding:8px 11px;border:none;background:none;width:100%;text-align:left;cursor:pointer;color:var(--txt);border-bottom:1px solid var(--line);font-size:.84rem;font-family:inherit}' +
  '.em-tool:last-child{border-bottom:none}' +
  '.em-tool:hover{background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
  '.em-tool.on{background:color-mix(in srgb,var(--acc) 14%,transparent);color:var(--acc)}' +
  '.em-tool .em-tool-g{font-size:.75rem;color:var(--mut);white-space:nowrap}' +
  '.em-tool.on .em-tool-g{color:var(--acc)}' +
  '.em-checks{display:flex;flex-direction:column;gap:9px;margin-top:4px}' +
  '.em-check{display:flex;align-items:center;gap:9px;font-size:.84rem;color:var(--txt-2);cursor:pointer}' +
  '.em-check input{width:auto;margin:0;accent-color:var(--acc)}' +
  '.em-preview-box{border:1px solid var(--line);border-radius:6px;overflow:hidden;background:var(--card2);min-height:220px}' +
  '.em-preview-box iframe{display:block;width:100%;border:0;background:var(--bg)}' +
  '.em-prev-note{font-size:.75rem;color:var(--mut);margin:6px 0 0}' +
  '.em-codehead{display:flex;justify-content:space-between;align-items:center;gap:10px;margin:0 0 6px}' +
  '.em-codehead h3{margin:0;font-size:.875rem;font-weight:600;color:var(--txt)}' +
  '.em-code{margin:0;background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:11px 12px;font-family:var(--font-mono);font-size:.76rem;line-height:1.55;color:var(--txt-2);white-space:pre-wrap;word-break:break-word;overflow-x:auto;max-height:230px;overflow-y:auto}' +
  '.em-codeblock{margin:0 0 16px}' +
  '.em-codeblock p{margin:0 0 6px;font-size:.78rem;color:var(--mut);line-height:1.45}' +
  '.em-note{font-size:.82rem;color:var(--txt-2);line-height:1.6}' +
  '.em-note li{margin:3px 0}' +
  '</style>';

export function renderEmbedSDK(main) {
  const TOOLS = embeddableTools();

  // Current configuration (safe defaults).
  const cfg = {
    sec: TOOLS.length ? TOOLS[0].sec : "dns",
    width: "100%",
    height: 640,
    radius: true,
    showLink: true,
  };

  main.innerHTML = EM_CSS +
    '<div class="em-wrap">' +
      '<div class="pg-head"><div>' +
        '<h1 class="pg-h1">Embed SDK</h1>' +
        '<p class="muted pg-sub">Build iframe markup that shows a single Darknode tool in embed mode. Framing is limited to Darknode-origin pages, so these snippets do not work on other domains.</p>' +
      '</div></div>' +
      '<div class="em-grid">' +
        // ── Left: configuration ──
        '<div class="panel" style="padding:16px">' +
          '<div class="em-field">' +
            '<label class="em-label" for="emSearch">Tool</label>' +
            '<input class="em-input" id="emSearch" type="search" placeholder="Search tools" autocomplete="off" spellcheck="false">' +
            '<div class="em-tools" id="emTools" role="listbox" aria-label="Embeddable tools"></div>' +
          '</div>' +
          '<div class="em-row">' +
            '<div class="em-field">' +
              '<label class="em-label" for="emWidth">Width</label>' +
              '<input class="em-input" id="emWidth" value="100%">' +
            '</div>' +
            '<div class="em-field">' +
              '<label class="em-label" for="emHeight">Height (px)</label>' +
              '<input class="em-input" id="emHeight" type="number" min="120" max="4000" value="640">' +
            '</div>' +
          '</div>' +
          '<div class="em-field">' +
            '<div class="em-checks">' +
              '<label class="em-check"><input type="checkbox" id="emRadius" checked> Rounded corners (8px)</label>' +
              '<label class="em-check"><input type="checkbox" id="emLink" checked> Show an "Open in Darknode" link below the frame</label>' +
            '</div>' +
          '</div>' +
        '</div>' +
        // ── Right: preview + output ──
        '<div>' +
          '<div class="panel" style="padding:16px;margin-bottom:16px">' +
            '<div class="em-codehead"><h3>Preview</h3></div>' +
            '<div class="em-preview-box" id="emPreviewBox"></div>' +
            '<p class="em-prev-note" id="emPrevNote"></p>' +
          '</div>' +
          '<div class="panel" style="padding:16px">' +
            '<div class="em-codeblock">' +
              '<div class="em-codehead"><h3>Iframe snippet</h3><button class="btn sm" data-copy="iframe">Copy</button></div>' +
              '<pre class="em-code" id="emCodeIframe"></pre>' +
            '</div>' +
            '<div class="em-codeblock">' +
              '<div class="em-codehead"><h3>Responsive wrapper</h3><button class="btn sm" data-copy="responsive">Copy</button></div>' +
              '<p>Keeps the tool\'s aspect ratio as the container resizes.</p>' +
              '<pre class="em-code" id="emCodeResponsive"></pre>' +
            '</div>' +
            '<div class="em-codeblock">' +
              '<div class="em-codehead"><h3>JS loader</h3><button class="btn sm" data-copy="loader">Copy</button></div>' +
              '<p>Drop this once, then add <code>&lt;div data-darknode-tool="&hellip;"&gt;</code> anywhere on the page.</p>' +
              '<pre class="em-code" id="emCodeLoader"></pre>' +
            '</div>' +
          '</div>' +
          '<div class="panel" style="padding:16px;margin-top:16px">' +
            '<div class="em-codehead"><h3>How it works and limits</h3></div>' +
            '<ul class="em-note" style="margin:0;padding-left:18px">' +
              '<li>Each embed loads a Darknode route with <code>?embed=1</code>, which strips all chrome and renders only that one tool.</li>' +
              '<li>Framing is allowed same-origin only (<code>frame-ancestors \'self\'</code>). The embed must live on a Darknode-origin page; browsers refuse to render it inside any other domain.</li>' +
              '<li>The viewer must be signed in to Darknode. A same-origin iframe inherits the existing Firebase session, so there is no extra login step.</li>' +
              '<li>Embedded tools always render in the light theme.</li>' +
            '</ul>' +
          '</div>' +
        '</div>' +
      '</div>' +
    '</div>';

  const $ = (sel) => main.querySelector(sel);
  const toolsEl = $("#emTools");
  const searchEl = $("#emSearch");
  const widthEl = $("#emWidth");
  const heightEl = $("#emHeight");
  const radiusEl = $("#emRadius");
  const linkEl = $("#emLink");
  const previewBox = $("#emPreviewBox");
  const prevNote = $("#emPrevNote");
  const codeIframe = $("#emCodeIframe");
  const codeResponsive = $("#emCodeResponsive");
  const codeLoader = $("#emCodeLoader");

  function labelOf(sec) {
    const t = TOOLS.find((x) => x.sec === sec);
    return t ? t.label : sec;
  }

  // Build the embed URL for a sec using the live origin so it works anywhere.
  function embedUrl(sec) {
    let origin = "";
    try { origin = window.location.origin; } catch (_) {}
    const q = "?embed=1";
    return origin + "/" + sec + q;
  }

  // ── Tool picker ──
  function renderTools() {
    const q = (searchEl.value || "").trim().toLowerCase();
    const hits = TOOLS.filter((t) =>
      !q || t.label.toLowerCase().includes(q) || t.sec.toLowerCase().includes(q) || t.group.toLowerCase().includes(q));
    if (!hits.length) {
      toolsEl.innerHTML = '<div class="em-tool" style="cursor:default;color:var(--mut)">No tools match that search.</div>';
      return;
    }
    toolsEl.innerHTML = hits.map((t) =>
      '<button class="em-tool' + (t.sec === cfg.sec ? " on" : "") + '" data-sec="' + esc(t.sec) + '" role="option" aria-selected="' + (t.sec === cfg.sec) + '">' +
        '<span>' + esc(t.label) + '</span>' +
        '<span class="em-tool-g">' + esc(t.group) + '</span>' +
      '</button>').join("");
  }

  toolsEl.onclick = (e) => {
    const btn = e.target.closest(".em-tool");
    if (!btn || !btn.dataset.sec) return;
    cfg.sec = btn.dataset.sec;
    renderTools();
    refresh();
  };
  searchEl.oninput = renderTools;

  // ── Options wiring ──
  widthEl.oninput = () => { cfg.width = (widthEl.value || "100%").trim() || "100%"; refresh(); };
  heightEl.oninput = () => {
    let h = parseInt(heightEl.value, 10);
    if (!Number.isFinite(h)) h = 640;
    cfg.height = Math.max(120, Math.min(4000, h));
    refresh();
  };
  radiusEl.onchange = () => { cfg.radius = radiusEl.checked; refresh(); };
  linkEl.onchange = () => { cfg.showLink = linkEl.checked; refresh(); };

  // ── Snippet generators (all strings; shown escaped, copied as-is) ──
  function iframeSnippet() {
    // Emit an absolute URL from the current origin, so the snippet works on darknode.ai and
    // in local previews alike. The responsive and loader snippets compute origin at runtime.
    return buildIframe({ origin: currentOrigin() });
  }

  function currentOrigin() {
    try { return window.location.origin; } catch (_) { return "https://darknode.ai"; }
  }

  function buildIframe(opts) {
    const origin = opts.origin;
    const style =
      "border:0;width:" + cfg.width + ";height:" + cfg.height + "px;" +
      (cfg.radius ? "border-radius:8px;" : "");
    let html =
      '<iframe\n' +
      '  src="' + origin + '/' + cfg.sec + '?embed=1"\n' +
      '  title="' + labelOf(cfg.sec) + ' — Darknode"\n' +
      '  loading="lazy"\n' +
      '  style="' + style + '">\n' +
      '</iframe>';
    if (cfg.showLink) {
      html +=
        '\n<p style="font:13px system-ui;margin:6px 0 0">' +
        '<a href="' + origin + '/' + cfg.sec + '" target="_blank" rel="noopener">Open in Darknode</a>' +
        '</p>';
    }
    return html;
  }

  function responsiveSnippet() {
    const origin = currentOrigin();
    // Aspect ratio from the chosen height against a 1000px reference width.
    const ratio = Math.max(20, Math.min(400, Math.round((cfg.height / 1000) * 10000) / 100));
    const radius = cfg.radius ? "border-radius:8px;" : "";
    let html =
      '<div style="position:relative;width:' + cfg.width + ';padding-top:' + ratio + '%">\n' +
      '  <iframe\n' +
      '    src="' + origin + '/' + cfg.sec + '?embed=1"\n' +
      '    title="' + labelOf(cfg.sec) + ' — Darknode"\n' +
      '    loading="lazy"\n' +
      '    style="position:absolute;inset:0;width:100%;height:100%;border:0;' + radius + '">\n' +
      '  </iframe>\n' +
      '</div>';
    if (cfg.showLink) {
      html +=
        '\n<p style="font:13px system-ui;margin:6px 0 0">' +
        '<a href="' + origin + '/' + cfg.sec + '" target="_blank" rel="noopener">Open in Darknode</a>' +
        '</p>';
    }
    return html;
  }

  // Self-contained ~15-line IIFE loader: finds data-darknode-tool divs and injects iframes.
  function loaderSnippet() {
    const h = cfg.height;
    const radius = cfg.radius ? "8px" : "0";
    const link = cfg.showLink ? "true" : "false";
    return [
      '<script>',
      '(function () {',
      '  var ORIGIN = location.origin;',
      '  var nodes = document.querySelectorAll("[data-darknode-tool]");',
      '  for (var i = 0; i < nodes.length; i++) {',
      '    var el = nodes[i], sec = el.getAttribute("data-darknode-tool");',
      '    if (!sec || el.getAttribute("data-dn-done")) continue;',
      '    var h = el.getAttribute("data-height") || "' + h + '";',
      '    var f = document.createElement("iframe");',
      '    f.src = ORIGIN + "/" + sec + "?embed=1";',
      '    f.loading = "lazy"; f.title = "Darknode — " + sec;',
      '    f.style.cssText = "border:0;width:100%;height:" + h + "px;border-radius:' + radius + '";',
      '    el.appendChild(f);',
      '    if (' + link + ') { var a = document.createElement("a"); a.href = ORIGIN + "/" + sec;',
      '      a.target = "_blank"; a.rel = "noopener"; a.textContent = "Open in Darknode";',
      '      a.style.cssText = "display:block;font:13px system-ui;margin-top:6px"; el.appendChild(a); }',
      '    el.setAttribute("data-dn-done", "1");',
      '  }',
      '})();',
      '<\/script>',
      '',
      '<!-- then, anywhere on the page: -->',
      '<div data-darknode-tool="' + cfg.sec + '"></div>',
    ].join("\n");
  }

  // ── Live preview ──
  function renderPreview() {
    const url = embedUrl(cfg.sec);
    const radius = cfg.radius ? "border-radius:8px;" : "";
    previewBox.innerHTML =
      '<iframe src="' + esc(url) + '" title="Preview: ' + esc(labelOf(cfg.sec)) + '" ' +
      'loading="lazy" sandbox="allow-scripts allow-same-origin allow-forms allow-popups" ' +
      'style="width:' + esc(cfg.width) + ';height:' + Math.min(cfg.height, 520) + 'px;' + radius + '"></iframe>';
    prevNote.textContent = "Previewing " + labelOf(cfg.sec) + " at " + cfg.sec + "?embed=1. " +
      "The embed inherits your current Darknode sign-in.";
  }

  // ── Output refresh ──
  function refresh() {
    // Code boxes: set via textContent so the markup shows as visible, escaped text.
    codeIframe.textContent = iframeSnippet();
    codeResponsive.textContent = responsiveSnippet();
    codeLoader.textContent = loaderSnippet();
    renderPreview();
  }

  // ── Copy buttons ──
  main.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-copy]");
    if (!btn) return;
    const map = { iframe: codeIframe, responsive: codeResponsive, loader: codeLoader };
    const src = map[btn.dataset.copy];
    if (!src) return;
    const text = src.textContent;
    const done = () => toast("Copied " + btn.dataset.copy + " snippet to clipboard");
    const fallback = () => {
      try {
        const ta = document.createElement("textarea");
        ta.value = text; ta.style.position = "fixed"; ta.style.opacity = "0";
        document.body.appendChild(ta); ta.select();
        document.execCommand("copy"); ta.remove(); done();
      } catch (_) { toast("Select the snippet text and copy it manually"); }
    };
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, fallback);
      } else { fallback(); }
    } catch (_) { fallback(); }
  });

  renderTools();
  refresh();
}
