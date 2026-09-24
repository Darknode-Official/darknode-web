// Searchable, categorized tools catalog as an accordion. Each row shows name +
// description; the triangle expands to reveal the command + copy (local tools) or
// the working tool panel (browser tools). An enterprise toolbar on top provides
// live search, Web/Local kind filters, and category filter chips with counts.
import { CATALOG, CATEGORIES } from "/js/toolkit.js";
import { isBookmarked, toggleBookmark } from "/js/saved.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderTools(el) {
  if (!el) return;

  const webCount = CATALOG.filter((t) => t.kind === "browser").length;
  const localCount = CATALOG.length - webCount;
  const catCounts = {};
  CATEGORIES.forEach((c) => { catCounts[c] = CATALOG.filter((t) => t.cat === c).length; });

  el.innerHTML = `
    <div class="tk-toolbar">
      <div class="tk-toolbar-row">
        <div class="tk-search-wrap">
          <span class="tk-search-ico" aria-hidden="true"></span>
          <input class="tk-search" id="tk-search" placeholder="Search ${CATALOG.length} tools by name, category, or what they do...">
        </div>
        <div class="tk-kind" id="tk-kind">
          <button class="tk-kchip on" data-kind="">All <span class="tk-kn">${CATALOG.length}</span></button>
          <button class="tk-kchip" data-kind="browser">Web <span class="tk-kn">${webCount}</span></button>
          <button class="tk-kchip" data-kind="local">Local <span class="tk-kn">${localCount}</span></button>
        </div>
      </div>
      <div class="tk-catnav" id="tk-catnav" role="tablist" aria-label="Tool categories">
        <button class="tk-catchip on" data-cat="">All categories</button>
        ${CATEGORIES.map((c) => `<button class="tk-catchip" data-cat="${esc(c)}">${esc(c)}<span class="tk-cn">${catCounts[c]}</span></button>`).join("")}
      </div>
      <div class="tk-count muted" id="tk-count"></div>
    </div>
    <div class="tk-cats" id="tk-cats"></div>`;

  const cats = el.querySelector("#tk-cats");
  const countEl = el.querySelector("#tk-count");
  let curTerm = "", curKind = "", curCat = "";

  const row = (t) => `
    <div class="tk-item" data-id="${t.id}">
      <button class="tk-head" aria-expanded="false">
        <span class="tk-tri"></span>
        <span class="tk-name">${esc(t.name)}</span>
        <span class="tk-desc">${esc(t.desc)}</span>
        <span class="tk-badge ${t.kind}">${t.kind === "browser" ? "web" : "local"}</span>
        <span class="tk-star${isBookmarked(t.id) ? " on" : ""}" data-star="${esc(t.id)}" data-label="${esc(t.name)}" title="Bookmark">${isBookmarked(t.id) ? "*" : "-"}</span>
      </button>
      <div class="tk-panel" hidden></div>
    </div>`;

  function draw() {
    const term = curTerm.toLowerCase().trim();
    const items = CATALOG.filter((t) =>
      (!term || (t.name + " " + t.desc + " " + t.cat).toLowerCase().includes(term)) &&
      (!curKind || t.kind === curKind) &&
      (!curCat || t.cat === curCat));
    const shownCats = (curCat ? CATEGORIES.filter((c) => c === curCat) : CATEGORIES);
    cats.innerHTML = shownCats.map((c) => {
      const list = items.filter((t) => t.cat === c);
      if (!list.length) return "";
      return `<div class="tk-cat"><div class="tk-cat-h">${esc(c)} <span class="tk-cat-n">${list.length}</span></div>${list.map(row).join("")}</div>`;
    }).join("") || `<p class="muted tk-empty">No tools match your filters.</p>`;
    countEl.textContent = `Showing ${items.length} of ${CATALOG.length} tools` +
      (curCat ? ` in ${curCat}` : "") + (curKind ? ` (${curKind === "browser" ? "web" : "local"} only)` : "");
  }

  function fill(item, t) {
    if (item.dataset.filled) return;
    const panel = item.querySelector(".tk-panel");
    if (t.kind === "browser") {
      t.render(panel);
    } else {
      panel.innerHTML = `<div class="dl-cmd-row"><code class="dl-cmd">${esc(t.cmd)}</code><button class="dl-copy tk-copy">copy</button></div>`;
      panel.querySelector(".tk-copy").onclick = (ev) =>
        navigator.clipboard?.writeText(t.cmd).then(() => { ev.target.textContent = "copied"; setTimeout(() => (ev.target.textContent = "copy"), 1200); });
    }
    item.dataset.filled = "1";
  }

  cats.onclick = (e) => {
    const star = e.target.closest(".tk-star");
    if (star) { e.stopPropagation(); toggleBookmark({ id: star.dataset.star, label: star.dataset.label, sec: "tools" }); const on = isBookmarked(star.dataset.star); star.classList.toggle("on", on); star.textContent = on ? "*" : "-"; return; }
    const head = e.target.closest(".tk-head"); if (!head) return;
    const item = head.closest(".tk-item");
    const t = CATALOG.find((x) => x.id === item.dataset.id);
    const panel = item.querySelector(".tk-panel");
    const open = item.classList.toggle("open");
    head.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) { fill(item, t); panel.hidden = false; } else { panel.hidden = true; }
  };

  // Kind filter chips (All / Web / Local)
  el.querySelector("#tk-kind").onclick = (e) => {
    const chip = e.target.closest(".tk-kchip"); if (!chip) return;
    curKind = chip.dataset.kind;
    el.querySelectorAll("#tk-kind .tk-kchip").forEach((b) => b.classList.toggle("on", b === chip));
    draw();
  };

  // Category filter chips
  el.querySelector("#tk-catnav").onclick = (e) => {
    const chip = e.target.closest(".tk-catchip"); if (!chip) return;
    curCat = chip.dataset.cat;
    el.querySelectorAll("#tk-catnav .tk-catchip").forEach((b) => b.classList.toggle("on", b === chip));
    draw();
  };

  el.querySelector("#tk-search").oninput = (e) => { curTerm = e.target.value; draw(); };
  draw();
}
