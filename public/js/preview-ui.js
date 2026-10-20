// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Preview UI — a light, spacious, single-surface reimagining of the console: every
// tool from the console nav (the same NAV the Deck is built from) laid out as a calm,
// searchable catalogue. It mounts as a full-screen overlay, carries its own scoped
// styles (prefix .pvx) so it never collides with the console/Deck cascade, and routes
// a tool open by clicking that section's real hidden `.side-item[data-sec]` — so nothing
// here is a dead link. renderPreview(root, opts) returns a teardown function.

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Group color names (console-nav + toolkit categories) → a soft, light-mode-friendly hue.
// Anything unmapped falls back to a neutral slate so a dot never renders empty.
const HUE = {
  blue: "#3b6fe0", cyan: "#1aa6b7", orange: "#e8873b", red: "#e2555f", green: "#2faa6a",
  purple: "#8a63d2", violet: "#7a5cf0", emerald: "#1fa97e", teal: "#179a9a", slate: "#64748b",
  pink: "#d6559c", amber: "#d99b2b", indigo: "#5468e0", lime: "#5a9e2f", rose: "#dd5a77",
};
const hue = (c) => HUE[c] || "#64748b";

const BADGE = { live: "Live", ai: "AI", beta: "Beta", new: "New" };
const badgeHTML = (b) => (b && BADGE[b] ? ` <span class="pvx-badge pvx-b-${b}">${BADGE[b]}</span>` : "");

let styled = false;
function injectStyles() {
  if (styled || document.getElementById("pvx-style")) { styled = true; return; }
  const el = document.createElement("style");
  el.id = "pvx-style";
  el.textContent = `
.pvx{position:fixed;inset:0;z-index:4000;display:flex;flex-direction:column;
  background:#fbfcfe;color:#1b2432;font:400 15px/1.5 ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  -webkit-font-smoothing:antialiased;overflow:hidden;animation:pvx-in .18s ease}
@keyframes pvx-in{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}
.pvx *,.pvx *::before,.pvx *::after{box-sizing:border-box}
.pvx button{font:inherit;color:inherit;cursor:pointer}
.pvx-top{position:sticky;top:0;flex:none;display:flex;align-items:center;gap:18px;flex-wrap:wrap;
  padding:16px 28px;background:rgba(251,252,254,.82);backdrop-filter:saturate(1.3) blur(10px);
  border-bottom:1px solid #eceef2;z-index:2}
.pvx-brand{display:flex;flex-direction:column;gap:1px;margin-right:4px}
.pvx-ttl{font:650 17px/1.2 inherit;letter-spacing:-.01em}
.pvx-sub{font:400 12.5px/1.3 inherit;color:#7a828e}
.pvx-search{flex:1 1 280px;position:relative;min-width:200px;max-width:560px}
.pvx-search input{width:100%;padding:11px 40px 11px 38px;border:1px solid #e4e7ec;border-radius:11px;
  background:#fff;color:#1b2432;font:inherit;outline:none;transition:border-color .15s,box-shadow .15s}
.pvx-search input::placeholder{color:#9aa2ad}
.pvx-search input:focus{border-color:#b7c7f2;box-shadow:0 0 0 4px rgba(59,111,224,.1)}
.pvx-search svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:16px;height:16px;color:#9aa2ad;pointer-events:none}
.pvx-search kbd{position:absolute;right:11px;top:50%;transform:translateY(-50%);font:600 11px/1 ui-monospace,monospace;
  color:#9aa2ad;background:#f3f5f8;border:1px solid #e7eaef;border-radius:5px;padding:3px 6px}
.pvx-count{font:500 13px/1 inherit;color:#7a828e;white-space:nowrap}
.pvx-x{flex:none;width:36px;height:36px;display:grid;place-items:center;border:1px solid #e4e7ec;border-radius:10px;
  background:#fff;color:#5a6472;font-size:20px;line-height:1;transition:background .15s,color .15s,border-color .15s}
.pvx-x:hover{background:#f6f7f9;color:#1b2432;border-color:#d7dce3}
.pvx-wrap{flex:1;display:grid;grid-template-columns:232px 1fr;min-height:0}
.pvx-rail{border-right:1px solid #eceef2;overflow-y:auto;padding:16px 10px 28px;scrollbar-width:thin}
.pvx-rail-h{font:700 11px/1.4 inherit;letter-spacing:.08em;text-transform:uppercase;color:#98a0ab;padding:0 12px 8px}
.pvx-rl{display:flex;align-items:center;gap:9px;width:100%;text-align:left;border:0;background:transparent;
  padding:7px 12px;border-radius:9px;color:#495260;transition:background .12s,color .12s}
.pvx-rl:hover{background:#f1f3f7;color:#1b2432}
.pvx-rl.on{background:#eef2fe;color:#2a4bd0;font-weight:600}
.pvx-rl .pvx-dot{flex:none}
.pvx-rl-n{flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.pvx-rl-c{font:500 12px/1 inherit;color:#aeb5bf}
.pvx-rl.on .pvx-rl-c{color:#7f93e0}
.pvx-dot{width:9px;height:9px;border-radius:50%;background:var(--h,#64748b)}
.pvx-main{overflow-y:auto;padding:22px 32px 60px;scroll-behavior:smooth}
.pvx-sec{margin:0 0 30px;scroll-margin-top:16px}
.pvx-sh{display:flex;align-items:center;gap:10px;margin:0 0 14px}
.pvx-sh .pvx-dot{width:11px;height:11px}
.pvx-sh h2{font:650 16px/1.2 inherit;letter-spacing:-.01em;margin:0}
.pvx-sh-c{font:500 12px/1 inherit;color:#9aa2ad;background:#f1f3f7;border-radius:999px;padding:3px 9px}
.pvx-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(216px,1fr));gap:12px}
.pvx-card{display:flex;flex-direction:column;gap:5px;align-items:flex-start;text-align:left;
  padding:14px 15px;border:1px solid #ebeef2;border-radius:14px;background:#fff;
  box-shadow:0 1px 2px rgba(16,24,40,.03);transition:transform .14s ease,box-shadow .14s ease,border-color .14s ease}
.pvx-card:hover{transform:translateY(-2px);box-shadow:0 6px 18px rgba(16,24,40,.08);border-color:var(--h,#c9d2de)}
.pvx-card:focus-visible{outline:2px solid #3b6fe0;outline-offset:2px}
.pvx-card-n{font:550 14px/1.3 inherit;letter-spacing:-.005em}
.pvx-card-g{display:flex;align-items:center;gap:6px;font:500 12px/1 inherit;color:#8a929d}
.pvx-badge{font:700 9.5px/1 inherit;letter-spacing:.04em;text-transform:uppercase;padding:3px 6px;border-radius:5px;vertical-align:middle}
.pvx-b-live{color:#1f9d6b;background:#e5f6ee}
.pvx-b-ai{color:#7a5cf0;background:#efeafe}
.pvx-b-beta{color:#d98217;background:#fbf0e2}
.pvx-b-new{color:#2a6fe0;background:#e8f0fe}
.pvx-empty{padding:60px 20px;text-align:center;color:#8a929d}
.pvx-empty b{display:block;color:#5a6472;font-size:16px;margin-bottom:4px}
.pvx-sec[hidden]{display:none}
@media (max-width:760px){
  .pvx-wrap{grid-template-columns:1fr}
  .pvx-rail{display:none}
  .pvx-top{padding:14px 16px;gap:12px}
  .pvx-main{padding:18px 16px 56px}
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
      <button class="pvx-card" data-sec="${esc(i.sec)}" data-txt="${esc((i.label + " " + g.name).toLowerCase())}" style="--h:${h}">
        <span class="pvx-card-n">${esc(i.label)}${badgeHTML(i.badge)}</span>
        <span class="pvx-card-g"><span class="pvx-dot" style="--h:${h}"></span>${esc(g.name)}</span>
      </button>`).join("");
    return `<section class="pvx-sec" data-g="${esc(g.id)}">
      <div class="pvx-sh"><span class="pvx-dot" style="--h:${h}"></span><h2>${esc(g.name)}</h2><span class="pvx-sh-c">${g.items.length}</span></div>
      <div class="pvx-grid">${cards}</div>
    </section>`;
  }).join("");

  const railHTML = groups.map((g) => `<button class="pvx-rl" data-go="${esc(g.id)}">
    <span class="pvx-dot" style="--h:${hue(g.color)}"></span><span class="pvx-rl-n">${esc(g.name)}</span><span class="pvx-rl-c">${g.items.length}</span>
  </button>`).join("");

  const el = document.createElement("div");
  el.className = "pvx";
  el.setAttribute("role", "dialog");
  el.setAttribute("aria-label", "Tool preview");
  el.innerHTML = `
    <div class="pvx-top">
      <div class="pvx-brand"><span class="pvx-ttl">Darknode Preview</span><span class="pvx-sub">A calmer view of every tool</span></div>
      <label class="pvx-search">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg>
        <input id="pvxSearch" type="search" placeholder="Search ${total} tools" autocomplete="off" spellcheck="false" aria-label="Search tools">
        <kbd aria-hidden="true">/</kbd>
      </label>
      <span class="pvx-count" id="pvxCount">${total} tools &middot; ${groups.length} groups</span>
      <button class="pvx-x" id="pvxClose" aria-label="Close preview" title="Close">&times;</button>
    </div>
    <div class="pvx-wrap">
      <nav class="pvx-rail" aria-label="Categories">
        <div class="pvx-rail-h">Categories</div>
        ${railHTML}
      </nav>
      <div class="pvx-main" id="pvxMain">
        ${secHTML}
        <div class="pvx-empty" id="pvxEmpty" hidden><b>No matches</b><span>Try a different word, or clear the search.</span></div>
      </div>
    </div>`;
  root.appendChild(el);

  const search = el.querySelector("#pvxSearch");
  const main = el.querySelector("#pvxMain");
  const empty = el.querySelector("#pvxEmpty");
  const countEl = el.querySelector("#pvxCount");
  const rail = el.querySelector(".pvx-rail");
  const secs = [...el.querySelectorAll(".pvx-sec")];

  const filter = () => {
    const q = (search.value || "").trim().toLowerCase();
    let shown = 0;
    secs.forEach((s) => {
      let any = 0;
      s.querySelectorAll(".pvx-card").forEach((c) => {
        const hit = !q || c.dataset.txt.includes(q);
        c.hidden = !hit; if (hit) any++;
      });
      s.hidden = !any;
      shown += any;
    });
    empty.hidden = shown > 0;
    countEl.textContent = q ? `${shown} match${shown === 1 ? "" : "es"}` : `${total} tools · ${groups.length} groups`;
  };

  // Scroll-spy: highlight the rail entry for whichever section is nearest the top.
  const rls = [...el.querySelectorAll(".pvx-rl")];
  const spy = () => {
    const top = main.scrollTop + 24;
    let cur = secs[0];
    for (const s of secs) { if (!s.hidden && s.offsetTop <= top) cur = s; }
    rls.forEach((r) => r.classList.toggle("on", cur && r.dataset.go === cur.dataset.g));
  };

  const onClick = (e) => {
    const card = e.target.closest(".pvx-card[data-sec]");
    if (card) { const sec = card.dataset.sec; teardown(); openSection(sec); return; }
    const rl = e.target.closest(".pvx-rl[data-go]");
    if (rl) { const s = el.querySelector(`.pvx-sec[data-g="${CSS.escape(rl.dataset.go)}"]`); if (s) main.scrollTo({ top: s.offsetTop - 8, behavior: "smooth" }); return; }
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
