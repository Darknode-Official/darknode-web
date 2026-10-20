// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Preview UI — a light, premium, single-surface reimagining of the console: every tool
// from the console nav (the same NAV the Deck is built from) presented as an app-store
// style catalogue — a search-led hero, quick-filter chips, a grid/list toggle, and cover
// cards each led by a coloured app-icon tile. It mounts as a full-screen overlay, carries
// its own scoped styles (prefix .pvx) so it never collides with the console/Deck cascade,
// and routes a tool open by clicking that section's real hidden `.side-item[data-sec]` — so
// nothing here is a dead link. renderPreview(root, opts) returns a teardown function.

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Group color names (console-nav + toolkit categories) → a crisp, light-mode-friendly hue.
// Anything unmapped falls back to a neutral slate so a tile never renders empty.
const HUE = {
  blue: "#3f6ae6", cyan: "#0fa6bd", orange: "#ec8a3a", red: "#e24f63", green: "#22a86b",
  purple: "#8a5fe0", violet: "#7355f2", emerald: "#10a97c", teal: "#0f9c9c", slate: "#5b6676",
  pink: "#d9519e", amber: "#dd9a24", indigo: "#4f63e8", lime: "#58a42c", rose: "#e05478",
};
const hue = (c) => HUE[c] || "#5b6676";

// Two-letter monogram from a tool label — first letters of the first two words, or the
// first two characters of a single word. Letters/digits only, so symbols never leak in.
const mono = (label) => {
  const w = String(label || "").replace(/[^\p{L}\p{N}]+/gu, " ").trim().split(/\s+/).filter(Boolean);
  if (!w.length) return "··";
  if (w.length === 1) return w[0].slice(0, 2).toUpperCase();
  return (w[0][0] + w[1][0]).toUpperCase();
};

const BADGE = { live: "Live", ai: "AI", beta: "Beta", new: "New" };
const badgeHTML = (b) => (b && BADGE[b] ? `<span class="pvx-badge pvx-b-${b}">${BADGE[b]}</span>` : "");

const LS = "pvx:view";
const getView = () => { try { return localStorage.getItem(LS) === "list" ? "list" : "grid"; } catch (_) { return "grid"; } };
const setView = (v) => { try { localStorage.setItem(LS, v); } catch (_) {} };

let styled = false;
function injectStyles() {
  if (styled || document.getElementById("pvx-style")) { styled = true; return; }
  const el = document.createElement("style");
  el.id = "pvx-style";
  el.textContent = `
.pvx{--ink:#131722;--ink2:#58616f;--ink3:#8a92a1;--line:#eceef3;--line2:#e2e5ec;--surf:#fff;--accent:#4b63f0;
  --fill:#eef0f5;--fillh:#edf0f6;--mix:#fff;color-scheme:light dark;
  position:fixed;inset:0;z-index:4000;display:flex;flex-direction:column;color:var(--ink);
  font:400 15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;text-rendering:optimizeLegibility;overflow:hidden;
  background:linear-gradient(180deg,#fcfcfe 0%,#f6f7fb 100%);animation:pvx-in .2s cubic-bezier(.2,.7,.3,1)}
@keyframes pvx-in{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:none}}
@keyframes pvx-pop{from{opacity:0;transform:translateY(6px) scale(.985)}to{opacity:1;transform:none}}
.pvx *,.pvx *::before,.pvx *::after{box-sizing:border-box}
.pvx button{font:inherit;color:inherit;cursor:pointer;margin:0}
.pvx ::selection{background:rgba(75,99,240,.18)}

/* ── Header ───────────────────────────────────────────── */
.pvx-top{position:sticky;top:0;flex:none;display:flex;align-items:center;gap:14px;
  padding:13px 26px;background:rgba(252,252,254,.78);backdrop-filter:saturate(1.4) blur(14px);
  -webkit-backdrop-filter:saturate(1.4) blur(14px);border-bottom:1px solid var(--line);z-index:4}
.pvx-brand{display:flex;align-items:center;gap:11px}
.pvx-mark{flex:none;width:34px;height:34px;border-radius:10px;display:grid;place-items:center;
  background:linear-gradient(145deg,#5b7bff,#7355f2 60%,#9b57e8);color:#fff;font:800 16px/1 inherit;
  letter-spacing:-.02em;box-shadow:0 4px 13px rgba(99,91,242,.3),inset 0 1px 0 rgba(255,255,255,.4)}
.pvx-brand-t{display:flex;flex-direction:column;gap:0;line-height:1.12}
.pvx-ttl{font:700 15px/1.15 inherit;letter-spacing:-.015em}
.pvx-sub{font:500 11.5px/1.2 inherit;color:var(--ink3)}
.pvx-spacer{flex:1 1 0}
.pvx-seg{display:flex;align-items:center;gap:2px;padding:3px;background:var(--fill);border-radius:11px}
.pvx-seg button{width:34px;height:30px;display:grid;place-items:center;border:0;border-radius:8px;background:transparent;color:var(--ink3);transition:background .14s,color .14s,box-shadow .14s}
.pvx-seg button svg{width:16px;height:16px}
.pvx-seg button:hover{color:var(--ink2)}
.pvx-seg button.on{background:var(--surf);color:var(--ink);box-shadow:0 1px 3px rgba(16,24,40,.12)}
.pvx-x{flex:none;width:38px;height:38px;display:grid;place-items:center;border:1px solid var(--line2);
  border-radius:11px;background:var(--surf);color:var(--ink2);transition:background .15s,color .15s,border-color .15s,transform .1s}
.pvx-x svg{width:17px;height:17px}
.pvx-x:hover{background:var(--fillh);color:var(--ink);border-color:var(--line2)}
.pvx-x:active{transform:scale(.94)}

/* ── Hero ─────────────────────────────────────────────── */
.pvx-hero{flex:none;text-align:center;padding:40px 26px 28px;border-bottom:1px solid var(--line);
  background:radial-gradient(760px 300px at 50% -40%,rgba(75,99,240,.09),transparent 70%)}
.pvx-hero h1{margin:0;font:760 27px/1.15 inherit;letter-spacing:-.03em}
.pvx-hero p{margin:7px 0 0;font:460 14px/1.4 inherit;color:var(--ink2)}
.pvx-hs{display:flex;align-items:center;gap:11px;max-width:620px;margin:20px auto 0;height:52px;padding:0 16px;
  background:var(--surf);border:1px solid var(--line2);border-radius:14px;
  box-shadow:0 2px 8px rgba(16,24,40,.05);transition:border-color .16s,box-shadow .16s}
.pvx-hs:focus-within{border-color:#aab9f5;box-shadow:0 0 0 4px rgba(75,99,240,.12),0 2px 8px rgba(16,24,40,.05)}
.pvx-hs svg{flex:none;width:19px;height:19px;color:var(--ink3)}
.pvx-hs:focus-within svg{color:var(--accent)}
.pvx-hs input{flex:1;min-width:0;border:0;background:transparent;outline:none;color:var(--ink);font:450 16px/1 inherit}
.pvx-hs input::placeholder{color:var(--ink3)}
.pvx-hs input::-webkit-search-cancel-button{-webkit-appearance:none}
.pvx-kbd{flex:none;font:650 11px/1 ui-monospace,"SF Mono",Menlo,monospace;color:var(--ink3);
  background:var(--fill);border:1px solid var(--line2);border-bottom-width:2px;border-radius:6px;padding:4px 7px}
.pvx-chips{display:flex;flex-wrap:wrap;justify-content:center;gap:8px;margin:16px auto 0;max-width:640px}
.pvx-chip{display:inline-flex;align-items:center;gap:6px;border:1px solid var(--line2);background:var(--surf);
  color:var(--ink2);border-radius:999px;padding:7px 14px;font:550 13px/1 inherit;transition:background .14s,color .14s,border-color .14s,transform .1s}
.pvx-chip:hover{border-color:#cfd5df;color:var(--ink)}
.pvx-chip:active{transform:scale(.96)}
.pvx-chip.on{background:var(--ink);color:var(--surf);border-color:var(--ink)}
.pvx-chip .pvx-cdot{width:7px;height:7px;border-radius:50%}

/* ── Layout ───────────────────────────────────────────── */
.pvx-wrap{flex:1;display:grid;grid-template-columns:250px 1fr;min-height:0}
.pvx-rail{overflow-y:auto;padding:20px 12px 36px;scrollbar-width:thin;border-right:1px solid var(--line)}
.pvx-rail::-webkit-scrollbar{width:9px}
.pvx-rail::-webkit-scrollbar-thumb{background:#dfe3ea;border-radius:9px;border:3px solid transparent;background-clip:padding-box}
.pvx-rail-h{font:720 11px/1.4 inherit;letter-spacing:.09em;text-transform:uppercase;color:var(--ink3);padding:0 12px 10px}
.pvx-rl{display:flex;align-items:center;gap:11px;width:100%;text-align:left;border:0;background:transparent;
  padding:9px 12px;border-radius:10px;color:var(--ink2);position:relative;transition:background .12s,color .12s}
.pvx-rl:hover{background:var(--fillh);color:var(--ink)}
.pvx-rl.on{background:color-mix(in srgb,var(--h) 11%,var(--mix));color:var(--ink);font-weight:600}
.pvx-rl.on::before{content:"";position:absolute;left:3px;top:50%;transform:translateY(-50%);width:3px;height:17px;border-radius:3px;background:var(--h)}
.pvx-rl-n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13.5px}
.pvx-rl-c{font:600 11.5px/1 inherit;color:var(--ink3);background:var(--fill);border-radius:999px;padding:2px 8px;min-width:24px;text-align:center}
.pvx-rl.on .pvx-rl-c{color:var(--h);background:color-mix(in srgb,var(--h) 15%,var(--mix))}
.pvx-dot{flex:none;width:9px;height:9px;border-radius:50%;background:var(--h,#5b6676);box-shadow:0 0 0 3px color-mix(in srgb,var(--h,#5b6676) 16%,transparent)}
.pvx-rl .pvx-dot{box-shadow:none;width:8px;height:8px}

.pvx-main{overflow-y:auto;scroll-behavior:smooth;padding:28px 34px 76px}
.pvx-main::-webkit-scrollbar{width:11px}
.pvx-main::-webkit-scrollbar-thumb{background:#dde1e9;border-radius:11px;border:3px solid transparent;background-clip:padding-box}
.pvx-inner{max-width:1400px;margin:0 auto}
.pvx-sec{margin:0 0 40px;scroll-margin-top:20px}
.pvx-sh{display:flex;align-items:center;gap:11px;margin:0 0 16px}
.pvx-sh .pvx-dot{width:11px;height:11px}
.pvx-sh h2{font:700 17px/1.2 inherit;letter-spacing:-.02em;margin:0}
.pvx-sh-c{font:650 11.5px/1 inherit;color:var(--ink3);background:var(--fill);border-radius:999px;padding:4px 9px}
.pvx-sh-rule{flex:1;height:1px;background:linear-gradient(90deg,var(--line2),transparent)}

/* ── Cover cards (grid view) ──────────────────────────── */
.pvx-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(228px,1fr));gap:14px}
.pvx-card{display:flex;flex-direction:column;text-align:left;border:1px solid var(--line);border-radius:16px;
  background:var(--surf);overflow:hidden;box-shadow:0 1px 2px rgba(16,24,40,.03);
  transition:transform .16s cubic-bezier(.2,.7,.3,1),box-shadow .16s,border-color .16s}
.pvx-card:hover{transform:translateY(-3px);box-shadow:0 12px 28px rgba(16,24,40,.1);border-color:color-mix(in srgb,var(--h) 32%,var(--line))}
.pvx-card:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.pvx-cover{position:relative;height:104px;display:grid;place-items:center;border-bottom:1px solid var(--line);
  background:
    radial-gradient(74px 74px at 80% 22%,color-mix(in srgb,var(--h) 16%,transparent),transparent 72%),
    linear-gradient(158deg,color-mix(in srgb,var(--h) 9%,var(--mix)) 0%,var(--mix) 68%)}
.pvx-tile{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;color:#fff;
  font:800 18px/1 inherit;letter-spacing:.01em;
  background:linear-gradient(145deg,color-mix(in srgb,var(--h) 84%,var(--mix)),var(--h));
  box-shadow:0 6px 16px color-mix(in srgb,var(--h) 34%,transparent),inset 0 1px 0 rgba(255,255,255,.4);
  transition:transform .16s}
.pvx-card:hover .pvx-tile{transform:scale(1.06)}
.pvx-foot{flex:1;display:flex;flex-direction:column;gap:3px;padding:14px 15px}
.pvx-card-n{font:650 14.5px/1.3 inherit;letter-spacing:-.01em;display:flex;align-items:center;gap:7px}
.pvx-card-nt{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pvx-card-g{font:510 12.5px/1.2 inherit;color:var(--ink3);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pvx-badge{flex:none;font:750 9.5px/1 inherit;letter-spacing:.05em;text-transform:uppercase;padding:3px 6px;border-radius:6px}
.pvx-b-live{color:#128a5e;background:#e4f6ee}
.pvx-b-ai{color:#6f4ff0;background:#ede8fe}
.pvx-b-beta{color:#c9790f;background:#fbefdd}
.pvx-b-new{color:#2a63e0;background:#e6eefe}

/* ── List view ────────────────────────────────────────── */
.pvx[data-view=list] .pvx-grid{grid-template-columns:1fr;gap:7px}
.pvx[data-view=list] .pvx-card{flex-direction:row;align-items:center;border-radius:12px}
.pvx[data-view=list] .pvx-card:hover{transform:none;box-shadow:0 4px 14px rgba(16,24,40,.07)}
.pvx[data-view=list] .pvx-cover{height:auto;width:auto;border:0;background:none;padding:10px 0 10px 12px;place-items:center}
.pvx[data-view=list] .pvx-tile{width:38px;height:38px;border-radius:11px;font-size:14px}
.pvx[data-view=list] .pvx-card:hover .pvx-tile{transform:none}
.pvx[data-view=list] .pvx-foot{padding:10px 16px 10px 14px;gap:2px}

.pvx-empty{padding:72px 20px;text-align:center;color:var(--ink3);animation:pvx-pop .18s ease}
.pvx-empty-ic{width:52px;height:52px;margin:0 auto 14px;border-radius:14px;display:grid;place-items:center;background:var(--fill);color:var(--ink3)}
.pvx-empty-ic svg{width:24px;height:24px}
.pvx-empty b{display:block;color:var(--ink2);font:650 16px/1.3 inherit;margin-bottom:3px}
.pvx-sec[hidden],.pvx-card[hidden]{display:none}

/* ── Dark mode: follows the browser/OS theme (prefers-color-scheme) ──── */
@media (prefers-color-scheme:dark){
  .pvx{--ink:#e9ebf1;--ink2:#9aa3b2;--ink3:#6b7482;--line:#242a35;--line2:#2f3542;--surf:#171a22;--accent:#7e93ff;
    --fill:#20242e;--fillh:#262c37;--mix:#1b1f28;background:linear-gradient(180deg,#0e1014 0%,#13161e 100%)}
  .pvx-top{background:rgba(16,18,24,.74)}
  .pvx-hero{background:radial-gradient(760px 300px at 50% -40%,rgba(126,147,255,.1),transparent 70%)}
  .pvx-seg{background:#13161d}
  .pvx-seg button.on{background:#2a303c;color:var(--ink);box-shadow:0 1px 3px rgba(0,0,0,.45)}
  .pvx-x:hover{border-color:#39414f}
  .pvx-chip:hover{border-color:#3a4150}
  .pvx-card{box-shadow:0 1px 2px rgba(0,0,0,.28)}
  .pvx-card:hover{box-shadow:0 12px 28px rgba(0,0,0,.5)}
  .pvx-hs{box-shadow:0 2px 8px rgba(0,0,0,.3)}
  .pvx-rail::-webkit-scrollbar-thumb,.pvx-main::-webkit-scrollbar-thumb{background:#2c313c}
  .pvx-b-live{color:#4cd6a1;background:rgba(32,169,124,.16)}
  .pvx-b-ai{color:#ab91ff;background:rgba(115,85,242,.2)}
  .pvx-b-beta{color:#e6ad52;background:rgba(221,154,36,.16)}
  .pvx-b-new{color:#7a9dff;background:rgba(75,99,240,.2)}
}
@media (max-width:860px){
  .pvx-wrap{grid-template-columns:1fr}
  .pvx-rail{display:none}
  .pvx-top{padding:11px 16px}
  .pvx-brand .pvx-brand-t{display:none}
  .pvx-hero{padding:28px 16px 22px}
  .pvx-hero h1{font-size:22px}
  .pvx-main{padding:20px 16px 60px}
}`;
  document.head.appendChild(el);
  styled = true;
}

// Navigate to a section the way the console does: click its real hidden side-item. If the
// console shell isn't mounted (e.g. it was torn down), fall back to the hash route.
function openSection(sec) {
  const item = document.querySelector(`.side-item[data-sec="${CSS.escape(sec)}"]`);
  if (item) { item.click(); return; }
  try { location.hash = "#" + sec; } catch (_) {}
}

export function renderPreview(root, opts = {}) {
  injectStyles();
  const groups = (opts.groups || []).filter((g) => g && (g.items || []).length);
  const total = groups.reduce((n, g) => n + g.items.length, 0);

  const secHTML = groups.map((g) => {
    const h = hue(g.color);
    const cards = g.items.map((i) => `
      <button class="pvx-card" data-sec="${esc(i.sec)}" data-badge="${esc(i.badge || "")}" data-txt="${esc((i.label + " " + g.name).toLowerCase())}" style="--h:${h}" title="Open ${esc(i.label)}">
        <span class="pvx-cover" aria-hidden="true"><span class="pvx-tile">${esc(mono(i.label))}</span></span>
        <span class="pvx-foot">
          <span class="pvx-card-n"><span class="pvx-card-nt">${esc(i.label)}</span>${badgeHTML(i.badge)}</span>
          <span class="pvx-card-g">${esc(g.name)}</span>
        </span>
      </button>`).join("");
    return `<section class="pvx-sec" data-g="${esc(g.id)}">
      <div class="pvx-sh"><span class="pvx-dot" style="--h:${h}"></span><h2>${esc(g.name)}</h2><span class="pvx-sh-c">${g.items.length}</span><span class="pvx-sh-rule"></span></div>
      <div class="pvx-grid">${cards}</div>
    </section>`;
  }).join("");

  const railHTML = groups.map((g) => `<button class="pvx-rl" data-go="${esc(g.id)}" style="--h:${hue(g.color)}">
    <span class="pvx-dot" style="--h:${hue(g.color)}"></span><span class="pvx-rl-n">${esc(g.name)}</span><span class="pvx-rl-c">${g.items.length}</span>
  </button>`).join("");

  const CHIPS = [["all", "All tools"], ["live", "Live"], ["ai", "AI"], ["new", "New"], ["beta", "Beta"]];
  const chipHTML = CHIPS.map(([k, label], n) =>
    `<button class="pvx-chip${n === 0 ? " on" : ""}" data-chip="${k}">${label}</button>`).join("");

  const view = getView();
  const el = document.createElement("div");
  el.className = "pvx";
  el.dataset.view = view;
  el.setAttribute("role", "dialog");
  el.setAttribute("aria-label", "Tool preview");
  el.innerHTML = `
    <div class="pvx-top">
      <div class="pvx-brand">
        <span class="pvx-mark" aria-hidden="true">D</span>
        <span class="pvx-brand-t"><span class="pvx-ttl">Darknode</span><span class="pvx-sub">Tool catalogue</span></span>
      </div>
      <span class="pvx-spacer"></span>
      <div class="pvx-seg" role="group" aria-label="View">
        <button data-view="grid" class="${view === "grid" ? "on" : ""}" aria-label="Grid view" title="Grid"><svg viewBox="0 0 24 24" fill="currentColor"><rect x="3" y="3" width="8" height="8" rx="2"/><rect x="13" y="3" width="8" height="8" rx="2"/><rect x="3" y="13" width="8" height="8" rx="2"/><rect x="13" y="13" width="8" height="8" rx="2"/></svg></button>
        <button data-view="list" class="${view === "list" ? "on" : ""}" aria-label="List view" title="List"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round"><path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01"/></svg></button>
      </div>
      <button class="pvx-x" id="pvxClose" aria-label="Close preview" title="Close (Esc)">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M6 6l12 12M18 6L6 18"/></svg>
      </button>
    </div>
    <div class="pvx-hero">
      <h1>Every tool, one search</h1>
      <p id="pvxCount">${total} tools across ${groups.length} categories</p>
      <div class="pvx-hs">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input id="pvxSearch" type="search" placeholder="Search tools by name or category…" autocomplete="off" spellcheck="false" aria-label="Search tools">
        <kbd class="pvx-kbd" aria-hidden="true">/</kbd>
      </div>
      <div class="pvx-chips" role="group" aria-label="Quick filters">${chipHTML}</div>
    </div>
    <div class="pvx-wrap">
      <nav class="pvx-rail" aria-label="Categories">
        <div class="pvx-rail-h">Categories</div>
        ${railHTML}
      </nav>
      <div class="pvx-main" id="pvxMain">
        <div class="pvx-inner">
          ${secHTML}
          <div class="pvx-empty" id="pvxEmpty" hidden>
            <div class="pvx-empty-ic" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></div>
            <b>No tools match that</b><span>Try a different word, or clear the filters.</span>
          </div>
        </div>
      </div>
    </div>`;
  root.appendChild(el);

  const search = el.querySelector("#pvxSearch");
  const main = el.querySelector("#pvxMain");
  const empty = el.querySelector("#pvxEmpty");
  const countEl = el.querySelector("#pvxCount");
  const secs = [...el.querySelectorAll(".pvx-sec")];
  const chips = [...el.querySelectorAll(".pvx-chip")];
  const baseCount = `${total} tools across ${groups.length} categories`;
  let chip = "all";

  const filter = () => {
    const q = (search.value || "").trim().toLowerCase();
    let shown = 0;
    secs.forEach((s) => {
      let any = 0;
      s.querySelectorAll(".pvx-card").forEach((c) => {
        const hit = (!q || c.dataset.txt.includes(q)) && (chip === "all" || c.dataset.badge === chip);
        c.hidden = !hit; if (hit) any++;
      });
      s.hidden = !any;
      shown += any;
    });
    empty.hidden = shown > 0;
    const active = q || chip !== "all";
    countEl.textContent = active ? `${shown} ${shown === 1 ? "tool" : "tools"}` : baseCount;
  };

  // Scroll-spy: highlight the rail entry for whichever section is nearest the top.
  const rls = [...el.querySelectorAll(".pvx-rl")];
  const spy = () => {
    const top = main.scrollTop + 28;
    let cur = secs.find((s) => !s.hidden) || secs[0];
    for (const s of secs) { if (!s.hidden && s.offsetTop <= top) cur = s; }
    rls.forEach((r) => r.classList.toggle("on", cur && r.dataset.go === cur.dataset.g));
  };

  const applyView = (v) => {
    el.dataset.view = v; setView(v);
    el.querySelectorAll(".pvx-seg button").forEach((b) => b.classList.toggle("on", b.dataset.view === v));
    spy();
  };

  const onClick = (e) => {
    const card = e.target.closest(".pvx-card[data-sec]");
    if (card) { const sec = card.dataset.sec; teardown(); openSection(sec); return; }
    const seg = e.target.closest(".pvx-seg button[data-view]");
    if (seg) { applyView(seg.dataset.view); return; }
    const ch = e.target.closest(".pvx-chip[data-chip]");
    if (ch) { chip = ch.dataset.chip; chips.forEach((c) => c.classList.toggle("on", c === ch)); filter(); spy(); main.scrollTo({ top: 0, behavior: "smooth" }); return; }
    const rl = e.target.closest(".pvx-rl[data-go]");
    if (rl) { const s = el.querySelector(`.pvx-sec[data-g="${CSS.escape(rl.dataset.go)}"]`); if (s) main.scrollTo({ top: s.offsetTop - 10, behavior: "smooth" }); return; }
    if (e.target.closest("#pvxClose")) { teardown(); }
  };
  const onKey = (e) => {
    if (e.key === "Escape") { e.preventDefault(); teardown(); return; }
    const t = e.target, typing = t && (t.tagName === "INPUT" || t.tagName === "TEXTAREA");
    if (e.key === "/" && !typing) { e.preventDefault(); search.focus(); }
  };

  el.addEventListener("click", onClick);
  search.addEventListener("input", filter);
  main.addEventListener("scroll", spy, { passive: true });
  document.addEventListener("keydown", onKey);
  document.body.style.overflow = "hidden";
  setTimeout(() => { try { search.focus(); } catch (_) {} spy(); }, 30);

  let done = false;
  function teardown() {
    if (done) return; done = true;
    document.removeEventListener("keydown", onKey);
    document.body.style.overflow = "";
    try { el.remove(); } catch (_) {}
    if (typeof opts.onExit === "function") { try { opts.onExit(); } catch (_) {} }
  }
  return teardown;
}
