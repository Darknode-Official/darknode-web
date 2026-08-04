// Searchable, categorized tools catalog. Browser tools open a working panel in a
// modal; local tools show their install command (a website can't run them).
import { CATALOG, CATEGORIES } from "/js/toolkit.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderTools(el) {
  if (!el) return;
  el.innerHTML = `
    <input class="tk-search" id="tk-search" placeholder="Search ${CATALOG.length} tools by name, category, or what it does...">
    <div class="tk-cats" id="tk-cats"></div>
    <div class="tk-modal" id="tk-modal" hidden>
      <div class="tk-modal-box">
        <div class="tk-modal-hd"><span id="tk-modal-title"></span><button class="btn ghost sm" id="tk-modal-close">Close</button></div>
        <div class="tk-modal-body" id="tk-modal-body"></div>
      </div>
    </div>`;

  const cats = el.querySelector("#tk-cats");
  const card = (t) => `<button class="tk-card ${t.kind}" data-id="${t.id}">
    <span class="tk-badge">${t.kind === "browser" ? "web" : "local"}</span>
    <span class="tk-card-name">${esc(t.name)}</span>
    <span class="tk-card-desc">${esc(t.desc)}</span></button>`;

  function draw(q = "") {
    const term = q.toLowerCase().trim();
    const items = CATALOG.filter((t) => !term || (t.name + " " + t.desc + " " + t.cat).toLowerCase().includes(term));
    cats.innerHTML = CATEGORIES.map((c) => {
      const list = items.filter((t) => t.cat === c);
      if (!list.length) return "";
      return `<div class="tk-cat"><div class="tk-cat-h">${esc(c)} <span class="tk-cat-n">${list.length}</span></div>
        <div class="tk-grid">${list.map(card).join("")}</div></div>`;
    }).join("") || `<p class="muted">No tools match "${esc(q)}".</p>`;
  }

  const modal = el.querySelector("#tk-modal"), body = el.querySelector("#tk-modal-body"), title = el.querySelector("#tk-modal-title");
  const close = () => { modal.hidden = true; body.innerHTML = ""; };
  el.querySelector("#tk-modal-close").onclick = close;
  modal.onclick = (e) => { if (e.target === modal) close(); };

  function open(t) {
    title.textContent = t.name;
    body.innerHTML = "";
    if (t.kind === "browser") {
      t.render(body);
    } else {
      body.innerHTML = `<p class="muted">${esc(t.desc)} &mdash; runs on your machine (a website can't run it). Install:</p>
        <div class="dl-cmd-row"><code class="dl-cmd">${esc(t.cmd)}</code><button class="dl-copy" id="tk-copy">copy</button></div>`;
      body.querySelector("#tk-copy").onclick = (ev) =>
        navigator.clipboard?.writeText(t.cmd).then(() => { ev.target.textContent = "copied"; setTimeout(() => (ev.target.textContent = "copy"), 1200); });
    }
    modal.hidden = false;
  }

  el.querySelector("#tk-search").oninput = (e) => draw(e.target.value);
  cats.onclick = (e) => { const b = e.target.closest(".tk-card[data-id]"); if (b) open(CATALOG.find((t) => t.id === b.dataset.id)); };
  draw("");
}
