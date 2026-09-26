// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Mini-tools engine: a generic renderer for the declarative tool registry in
// /js/tools/*.js. Each tool is { id, name, cat, desc, tags, inputs, run } and
// runs entirely client-side. One engine renders every tool's form + live output,
// so adding a tool is data, not UI. See js/tools/_schema.md for the contract.
import { TOOLS, TOOL_CATS } from "/js/tools-registry.js?v=20260925g";
import { H } from "/js/tools/_helpers.js?v=20260925f";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const byId = (id) => TOOLS.find((t) => t.id === id);

function inputHTML(f, i) {
  const id = `mt_f_${i}`;
  const lab = `<label class="mt-lbl" for="${id}">${esc(f.label || f.k)}</label>`;
  if (f.type === "textarea")
    return `<div class="mt-field">${lab}<textarea id="${id}" class="mt-in mt-ta" data-k="${esc(f.k)}" rows="${f.rows || 6}" spellcheck="false" placeholder="${esc(f.placeholder || "")}">${esc(f.value || "")}</textarea></div>`;
  if (f.type === "select")
    return `<div class="mt-field mt-field-row">${lab}<select id="${id}" class="mt-in mt-sel" data-k="${esc(f.k)}">${(f.opts || []).map((o) => { const val = Array.isArray(o) ? o[0] : o; const txt = Array.isArray(o) ? o[1] : o; return `<option value="${esc(val)}"${String(f.value) === String(val) ? " selected" : ""}>${esc(txt)}</option>`; }).join("")}</select></div>`;
  if (f.type === "checkbox")
    return `<div class="mt-field mt-field-check"><label class="mt-check"><input id="${id}" type="checkbox" data-k="${esc(f.k)}"${f.value ? " checked" : ""}><span>${esc(f.label || f.k)}</span></label></div>`;
  if (f.type === "range")
    return `<div class="mt-field mt-field-row">${lab}<input id="${id}" class="mt-in mt-range" type="range" data-k="${esc(f.k)}" min="${f.min ?? 0}" max="${f.max ?? 100}" step="${f.step ?? 1}" value="${f.value ?? f.min ?? 0}"><output class="mt-rangev">${f.value ?? f.min ?? 0}</output></div>`;
  return `<div class="mt-field mt-field-row">${lab}<input id="${id}" class="mt-in" type="${esc(f.inputType || "text")}" data-k="${esc(f.k)}" spellcheck="false" placeholder="${esc(f.placeholder || "")}" value="${esc(f.value || "")}"></div>`;
}

export function renderMiniTool(main, id, opts = {}) {
  const t = byId(id);
  if (!t) { main.innerHTML = `<div class="mt-shell"><p class="mt-empty">Tool not found.</p></div>`; return; }
  const cat = TOOL_CATS[t.cat] || { name: t.cat, color: "slate" };
  main.innerHTML = `
    <div class="mt-shell" data-color="${esc(cat.color)}">
      <div class="mt-head">
        <button class="mt-back" id="mtBack" type="button">&larr; All tools</button>
        <div class="mt-crumb"><span class="svc-dot"></span>${esc(cat.name)}</div>
      </div>
      <h1 class="mt-title">${esc(t.name)}</h1>
      <p class="mt-desc">${esc(t.desc || "")}</p>
      <div class="mt-body">
        <form class="mt-form" id="mtForm" autocomplete="off">
          ${(t.inputs || []).map(inputHTML).join("")}
          ${t.button === false ? "" : `<div class="mt-actions"><button class="mt-run" id="mtRun" type="submit">${esc(t.button || "Run")}</button></div>`}
        </form>
        <div class="mt-outwrap">
          <div class="mt-outbar"><span>Output</span><button class="mt-copy" id="mtCopy" type="button">Copy</button></div>
          <pre class="mt-out" id="mtOut" aria-live="polite"></pre>
        </div>
      </div>
    </div>`;
  const form = main.querySelector("#mtForm");
  const outEl = main.querySelector("#mtOut");
  const live = t.live !== false; // most tools recompute as you type
  const readVals = () => {
    const v = {};
    form.querySelectorAll("[data-k]").forEach((el) => {
      v[el.dataset.k] = el.type === "checkbox" ? el.checked : el.value;
    });
    return v;
  };
  let seq = 0;
  const runNow = async () => {
    const my = ++seq;
    let res;
    try {
      res = await t.run(readVals(), H);
    } catch (e) {
      if (my !== seq) return;
      outEl.textContent = "Error: " + (e && e.message ? e.message : String(e));
      outEl.classList.add("err");
      return;
    }
    if (my !== seq) return;
    outEl.classList.remove("err");
    const text = res == null ? "" : typeof res === "object" && "out" in res ? res.out : String(res);
    if (res && typeof res === "object" && res.error) { outEl.textContent = res.error; outEl.classList.add("err"); return; }
    outEl.textContent = text;
  };
  form.addEventListener("submit", (e) => { e.preventDefault(); runNow(); });
  if (live) form.addEventListener("input", (e) => {
    const r = e.target.closest(".mt-range"); if (r) { const o = r.parentElement.querySelector(".mt-rangev"); if (o) o.textContent = r.value; }
    runNow();
  });
  main.querySelector("#mtCopy").onclick = () => {
    const txt = outEl.textContent || "";
    navigator.clipboard && navigator.clipboard.writeText(txt).then(() => {
      const b = main.querySelector("#mtCopy"); b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200);
    }).catch(() => {});
  };
  const back = main.querySelector("#mtBack");
  if (back) back.onclick = () => { if (opts.onBack) opts.onBack(); else if (window.__show) window.__show("toolbox"); };
  // Auto-run once if every input has a value (so the user sees output immediately).
  if (live) runNow();
}

export function renderToolbox(main, opts = {}) {
  const cats = Object.keys(TOOL_CATS);
  const byCat = {};
  TOOLS.forEach((t) => { (byCat[t.cat] = byCat[t.cat] || []).push(t); });
  main.innerHTML = `
    <div class="mt-hub">
      <div class="mt-hub-head">
        <h1 class="pg-h2" style="margin:0">Toolbox</h1>
        <span class="muted">${TOOLS.length} instant, private utilities — everything runs in your browser.</span>
      </div>
      <div class="mt-hub-search"><input id="mtSearch" type="search" placeholder="Search ${TOOLS.length} tools — type a name, e.g. &quot;base64&quot;" autocomplete="off" spellcheck="false"></div>
      <div class="mt-hub-body" id="mtHubBody">
        ${cats.filter((c) => byCat[c] && byCat[c].length).map((c) => {
          const cat = TOOL_CATS[c];
          return `<section class="mt-hub-cat" data-color="${esc(cat.color)}" data-cat="${esc(c)}">
            <div class="mt-hub-ch"><span class="svc-dot"></span>${esc(cat.name)}<span class="mt-hub-n">${byCat[c].length}</span></div>
            <div class="mt-hub-grid">${byCat[c].map((t) => `<button class="mt-card" data-open="${esc(t.id)}" title="${esc(t.desc || "")}"><span class="mt-card-n">${esc(t.name)}</span><span class="mt-card-d">${esc(t.desc || "")}</span></button>`).join("")}</div>
          </section>`;
        }).join("")}
      </div>
      <p class="mt-empty" id="mtNoHits" hidden>No tools match. Try another word.</p>
    </div>`;
  const open = (id) => { if (opts.onOpen) opts.onOpen(id); else if (window.__show) window.__show("tool-" + id); };
  main.querySelector("#mtHubBody").addEventListener("click", (e) => {
    const b = e.target.closest("[data-open]"); if (b) open(b.dataset.open);
  });
  const search = main.querySelector("#mtSearch");
  search.addEventListener("input", () => {
    const q = search.value.trim().toLowerCase();
    let any = false;
    main.querySelectorAll(".mt-hub-cat").forEach((sec) => {
      let shown = 0;
      sec.querySelectorAll(".mt-card").forEach((card) => {
        const t = byId(card.dataset.open);
        const hay = (t.name + " " + (t.desc || "") + " " + (t.tags || []).join(" ")).toLowerCase();
        const hit = !q || hay.includes(q);
        card.hidden = !hit; if (hit) { shown++; any = true; }
      });
      sec.hidden = shown === 0;
    });
    main.querySelector("#mtNoHits").hidden = any;
  });
  search.focus();
}
