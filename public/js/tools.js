// Searchable, categorized tools catalog as an accordion. Each row shows name +
// description; the triangle expands to reveal the command + copy (local tools) or
// the working tool panel (browser tools).
import { CATALOG, CATEGORIES } from "/js/toolkit.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderTools(el) {
  if (!el) return;
  el.innerHTML = `
    <input class="tk-search" id="tk-search" placeholder="Search ${CATALOG.length} tools by name, category, or what they do...">
    <div class="tk-cats" id="tk-cats"></div>`;
  const cats = el.querySelector("#tk-cats");

  const row = (t) => `
    <div class="tk-item" data-id="${t.id}">
      <button class="tk-head" aria-expanded="false">
        <span class="tk-tri"></span>
        <span class="tk-name">${esc(t.name)}</span>
        <span class="tk-desc">${esc(t.desc)}</span>
        <span class="tk-badge ${t.kind}">${t.kind === "browser" ? "web" : "local"}</span>
      </button>
      <div class="tk-panel" hidden></div>
    </div>`;

  function draw(q = "") {
    const term = q.toLowerCase().trim();
    const items = CATALOG.filter((t) => !term || (t.name + " " + t.desc + " " + t.cat).toLowerCase().includes(term));
    cats.innerHTML = CATEGORIES.map((c) => {
      const list = items.filter((t) => t.cat === c);
      if (!list.length) return "";
      return `<div class="tk-cat"><div class="tk-cat-h">${esc(c)} <span class="tk-cat-n">${list.length}</span></div>${list.map(row).join("")}</div>`;
    }).join("") || `<p class="muted">No tools match "${esc(q)}".</p>`;
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
    const head = e.target.closest(".tk-head"); if (!head) return;
    const item = head.closest(".tk-item");
    const t = CATALOG.find((x) => x.id === item.dataset.id);
    const panel = item.querySelector(".tk-panel");
    const open = item.classList.toggle("open");
    head.setAttribute("aria-expanded", open ? "true" : "false");
    if (open) { fill(item, t); panel.hidden = false; } else { panel.hidden = true; }
  };

  el.querySelector("#tk-search").oninput = (e) => draw(e.target.value);
  draw("");
}
