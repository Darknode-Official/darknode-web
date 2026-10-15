/**
 * DARKNODE — GenAI Security Crosswalk
 * An interactive explorer for the OWASP GenAI Security Project crosswalk:
 * 51 GenAI risks (LLM / Agentic / Agentic-Skills / Data-&-Governance Top 10s)
 * mapped to controls across 26 security & compliance frameworks (3,771 mappings).
 *
 * Browse by risk (see which frameworks cover it) or by framework (see which
 * risks it addresses). Filter by source list, severity, and framework; export
 * any view to CSV.
 *
 * Data: public/data/crosswalk.json — distilled from the upstream dataset
 * (metadata + framework/control mappings; heavy evidence arrays dropped).
 *
 * ATTRIBUTION — the crosswalk data is a derivative of the OWASP GenAI Security
 * Project "crosswalk" (https://github.com/GenAI-Security-Project/crosswalk),
 * used under CC BY-SA 4.0. This adaptation is likewise shared under CC BY-SA 4.0.
 */

import { buildMatrix, coverageGaps, coverageBreadth } from "./crosswalk-matrix.js?v=20261014a";

let _alive = false;

const SEV_RANK = { Critical: 0, High: 1, Medium: 2, Low: 3 };
const LIST_META = {
  "LLM-Top10-2026": { short: "LLM", color: "#3b82f6" },
  "Agentic-Top10-2026": { short: "Agentic", color: "#a855f7" },
  "AST-Top10-2026": { short: "Skills", color: "#06b6d4" },
  "DSGAI-2026": { short: "Data & Gov", color: "#10b981" },
};

const esc = (s) => { const d = document.createElement("div"); d.textContent = s == null ? "" : s; return d.innerHTML; };
const sevColor = (s) => ({ Critical: "#ef4444", High: "#f59e0b", Medium: "#eab308", Low: "#22c55e" }[s] || "var(--mut)");

const CSS = `
.cw-wrap{--cw-gap:14px;color:var(--txt)}
.cw-head{display:flex;align-items:flex-start;gap:16px;flex-wrap:wrap;margin-bottom:14px}
.cw-head .cw-htxt{flex:1;min-width:260px}
.cw-head h1{margin:0 0 4px;font-size:1.5rem;letter-spacing:-.01em}
.cw-head p{margin:0;color:var(--mut);font-size:.9rem;max-width:72ch}
.cw-stats{display:flex;gap:10px;flex-wrap:wrap}
.cw-stat{background:var(--card2,var(--card));border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:84px;text-align:center}
.cw-stat b{display:block;font-size:1.3rem;line-height:1.1;color:var(--acc)}
.cw-stat span{font-size:.72rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}
.cw-attrib{font-size:.74rem;color:var(--mut);margin:2px 0 14px;padding:8px 12px;border-left:3px solid var(--acc-line,var(--line));background:var(--bg2,transparent);border-radius:0 8px 8px 0}
.cw-attrib a{color:var(--acc)}
.cw-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:12px}
.cw-seg{display:inline-flex;border:1px solid var(--line);border-radius:9px;overflow:hidden}
.cw-seg button{border:0;background:transparent;color:var(--mut);padding:7px 14px;font-size:.84rem;cursor:pointer;font-weight:600}
.cw-seg button.on{background:var(--acc);color:#fff}
.cw-search{flex:1;min-width:200px;padding:8px 12px;border:1px solid var(--line);border-radius:9px;background:var(--card);color:var(--txt);font-size:.9rem}
.cw-filters{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;align-items:center}
.cw-chip{border:1px solid var(--line);background:var(--card);color:var(--mut);border-radius:999px;padding:5px 12px;font-size:.78rem;cursor:pointer;display:inline-flex;align-items:center;gap:6px}
.cw-chip.on{border-color:var(--acc);color:var(--txt);background:var(--acc-soft,var(--card2,var(--card)))}
.cw-chip .cw-dot{width:8px;height:8px;border-radius:50%}
.cw-flabel{font-size:.74rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em;margin-right:2px}
.cw-sel{padding:7px 10px;border:1px solid var(--line);border-radius:9px;background:var(--card);color:var(--txt);font-size:.84rem;max-width:220px}
.cw-export{margin-left:auto;padding:7px 12px;border:1px solid var(--line);border-radius:9px;background:var(--card);color:var(--txt);font-size:.82rem;cursor:pointer}
.cw-export:hover{border-color:var(--acc)}
.cw-cols{display:grid;grid-template-columns:minmax(260px,340px) 1fr;gap:var(--cw-gap);align-items:start}
.cw-list{border:1px solid var(--line);border-radius:12px;background:var(--card);max-height:72vh;overflow:auto}
.cw-grp{font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut);padding:10px 14px 6px;position:sticky;top:0;background:var(--card);border-bottom:1px solid var(--line);z-index:1}
.cw-item{display:flex;align-items:center;gap:10px;padding:10px 14px;border-bottom:1px solid var(--line);cursor:pointer}
.cw-item:last-child{border-bottom:0}
.cw-item:hover{background:var(--bg2,var(--card2,transparent))}
.cw-item.on{background:var(--acc-soft,var(--card2));box-shadow:inset 3px 0 0 var(--acc)}
.cw-id{font:600 .72rem ui-monospace,SFMono-Regular,monospace;padding:2px 7px;border-radius:6px;color:#fff;flex:none}
.cw-item .cw-nm{flex:1;font-size:.88rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cw-item .cw-cnt{font-size:.74rem;color:var(--mut);flex:none}
.cw-sev{width:9px;height:9px;border-radius:50%;flex:none}
.cw-detail{border:1px solid var(--line);border-radius:12px;background:var(--card);padding:0;min-height:300px;max-height:72vh;overflow:hidden;display:flex;flex-direction:column}
.cw-dhead{padding:16px 20px;border-bottom:1px solid var(--line);background:var(--bg2,var(--card2,transparent))}
.cw-dhead h2{margin:0 0 6px;font-size:1.15rem;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cw-badges{display:flex;gap:7px;flex-wrap:wrap;margin-top:6px}
.cw-b{font-size:.72rem;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.cw-b.sev{color:#fff;border:0}
.cw-dbody{padding:6px 0;overflow:auto;flex:1;min-height:0}
.cw-xall{margin-left:auto;font-size:.74rem;background:none;border:1px solid var(--line);color:var(--acc);border-radius:999px;padding:3px 10px;cursor:pointer}
.cw-fw{border-bottom:1px solid var(--line)}
.cw-fw:last-child{border-bottom:0}
.cw-fwh{display:flex;align-items:center;gap:10px;padding:11px 20px;cursor:pointer;user-select:none}
.cw-fwh:hover{background:var(--bg2,var(--card2,transparent))}
.cw-fwh .cw-caret{color:var(--mut);transition:transform .15s;flex:none;font-size:.7rem}
.cw-fw.open .cw-caret{transform:rotate(90deg)}
.cw-fwh .cw-fwn{flex:1;font-weight:600;font-size:.92rem}
.cw-fwh .cw-fwv{font-size:.72rem;color:var(--mut)}
.cw-fwh .cw-pill{font-size:.72rem;color:var(--mut);background:var(--bg2,var(--card2,transparent));border:1px solid var(--line);padding:2px 8px;border-radius:999px;flex:none}
.cw-ctrls{display:none;padding:0 20px 10px}
.cw-fw.open .cw-ctrls{display:block}
.cw-ctrl{display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:baseline;padding:7px 0;border-top:1px dashed var(--line)}
.cw-ctrl .cw-cid{font:600 .78rem ui-monospace,SFMono-Regular,monospace;color:var(--acc)}
.cw-ctrl .cw-cn{font-size:.86rem}
.cw-ctrl .cw-meta{display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end}
.cw-tag{font-size:.68rem;padding:2px 7px;border-radius:6px;border:1px solid var(--line);color:var(--mut);white-space:nowrap}
.cw-empty{padding:48px 20px;text-align:center;color:var(--mut)}
.cw-link{color:var(--acc);text-decoration:none;font-size:.74rem}
.cw-link:hover{text-decoration:underline}
@media(max-width:860px){.cw-cols{grid-template-columns:1fr}.cw-list{max-height:45vh}.cw-detail{max-height:none}}
/* Colours come in as --c, not an inline background: the pro theme whitens inline backgrounds that start with #0/#1. */
.cw-dot,.cw-id,.cw-sev,.cw-b.sev,.cw-mc{background:var(--c)}

/* ---- Matrix / heatmap ---- */
.cw-matrix{display:none}
.cw-matrix.on{display:block}
.cw-mwrap{border:1px solid var(--line);border-radius:12px;background:var(--card);overflow:auto;max-height:66vh}
.cw-m{border-collapse:separate;border-spacing:0;width:max-content;min-width:100%;font-size:.76rem}
.cw-m th,.cw-m td{border-bottom:1px solid var(--line);border-right:1px solid var(--line)}
.cw-m thead th{position:sticky;top:0;z-index:3;background:var(--card);vertical-align:bottom;padding:8px 6px;text-align:center;color:var(--mut);font-weight:600;min-width:66px;max-width:66px;line-height:1.2;white-space:normal;word-break:break-word}
.cw-m thead th.cw-corner{left:0;z-index:4;min-width:240px;max-width:240px;text-align:left;vertical-align:middle;color:var(--txt);font-size:.8rem}
.cw-m thead th a{color:var(--mut);text-decoration:none;display:block}
.cw-m thead th a:hover{color:var(--acc);text-decoration:underline}
.cw-m tbody th.cw-rowh{position:sticky;left:0;z-index:2;background:var(--card);min-width:240px;max-width:240px;text-align:left;padding:7px 10px;font-weight:600}
.cw-m tbody th.cw-rowh .cw-rwrap{display:flex;align-items:center;gap:8px}
.cw-m tbody th.cw-rowh .cw-nm{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:.8rem}
.cw-m tr.cw-grprow th{position:sticky;left:0;z-index:2;background:var(--bg2,var(--card2,var(--card)));text-align:left;padding:7px 10px;font-size:.72rem;text-transform:uppercase;letter-spacing:.07em;color:var(--mut)}
.cw-mc{text-align:center;color:var(--txt);font-variant-numeric:tabular-nums;padding:0;width:66px;min-width:66px}
.cw-mc.cell{cursor:pointer}
.cw-mc.cell:hover{outline:2px solid var(--acc);outline-offset:-2px}
.cw-mc.z{color:var(--mut);background:repeating-linear-gradient(45deg,transparent,transparent 4px,var(--line) 4px,var(--line) 5px)}
.cw-mlegend{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin:10px 0 2px;font-size:.74rem;color:var(--mut)}
.cw-mlegend .cw-sw{width:26px;height:14px;border-radius:4px;border:1px solid var(--line)}
.cw-mlegend .cw-sw.z{background:repeating-linear-gradient(45deg,transparent,transparent 4px,var(--line) 4px,var(--line) 5px)}

/* ---- Coverage-gap panel ---- */
.cw-gap{border:1px solid var(--line);border-radius:12px;background:var(--card);margin-top:16px;overflow:hidden}
.cw-gaphead{display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:12px 16px;border-bottom:1px solid var(--line);background:var(--bg2,var(--card2,transparent))}
.cw-gaphead h3{margin:0;font-size:1rem;flex:none}
.cw-gaphead .cw-gfw{margin-left:2px}
.cw-gapexp{margin-left:auto}
.cw-gapline{padding:12px 16px 4px;font-size:.92rem;color:var(--txt)}
.cw-gapline b{color:var(--acc)}
.cw-gapsub{padding:0 16px 10px;font-size:.78rem;color:var(--mut)}
.cw-gaplist{padding:4px 8px 12px}
.cw-grisk{display:grid;grid-template-columns:auto 1fr auto auto;gap:10px;align-items:center;padding:8px 10px;border-top:1px solid var(--line)}
.cw-grisk:first-child{border-top:0}
.cw-grisk .cw-nm{font-size:.88rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.cw-grisk .cw-breadth{font-size:.74rem;color:var(--mut);white-space:nowrap}
.cw-grisk .cw-breadth.thin{color:#ef4444}
.cw-gapfull{padding:28px 16px;text-align:center;color:var(--mut)}
`;

export function cleanupCrosswalk() { _alive = false; }

export async function renderCrosswalk(main) {
  _alive = true;
  if (!document.getElementById("cw-style")) {
    const st = document.createElement("style"); st.id = "cw-style"; st.textContent = CSS; document.head.appendChild(st);
  }
  main.innerHTML = `<div class="cw-wrap"><p class="muted" style="text-align:center;padding:48px">Loading GenAI Security Crosswalk…</p></div>`;

  let data;
  try {
    const res = await fetch("/data/crosswalk.json?v=20261009a");
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch (e) {
    if (!_alive) return;
    main.innerHTML = `<div class="cw-wrap"><div class="cw-empty">Couldn't load the crosswalk dataset (${esc(e.message)}).</div></div>`;
    return;
  }
  if (!_alive) return;

  const risks = data.risks || [];
  const frameworks = data.frameworks || [];
  const fwUrl = {}, fwVer = {};
  frameworks.forEach((f) => { fwUrl[f.name] = f.url; fwVer[f.name] = f.ver; });
  const t = data.meta.totals || {};

  // framework -> list of {risk, map} for framework mode + counts
  const fwIndex = new Map();
  risks.forEach((r) => r.maps.forEach((m) => {
    if (!fwIndex.has(m.f)) fwIndex.set(m.f, []);
    fwIndex.get(m.f).push({ risk: r, map: m });
  }));

  // ---- state ----
  const state = { mode: "risk", q: "", lists: new Set(), sevs: new Set(), fw: "", selRisk: risks[0] ? risks[0].id : null, selFw: frameworks[0] ? frameworks[0].name : null, gapFw: frameworks[0] ? frameworks[0].name : null };

  main.innerHTML = `
    <div class="cw-wrap">
      <div class="cw-head">
        <div class="cw-htxt">
          <h1>GenAI Security Crosswalk</h1>
          <p>Map OWASP GenAI risks to the security and compliance frameworks that govern them — and back again. Browse by risk to see coverage, or by framework to see what it addresses.</p>
        </div>
        <div class="cw-stats">
          <div class="cw-stat"><b>${t.risks ?? risks.length}</b><span>Risks</span></div>
          <div class="cw-stat"><b>${t.frameworks ?? frameworks.length}</b><span>Frameworks</span></div>
          <div class="cw-stat"><b>${(t.mappings ?? 0).toLocaleString()}</b><span>Mappings</span></div>
          <div class="cw-stat"><b>${(t.controls ?? 0).toLocaleString()}</b><span>Controls</span></div>
        </div>
      </div>
      <div class="cw-attrib">
        Crosswalk data derived from the <a href="https://github.com/GenAI-Security-Project/crosswalk" target="_blank" rel="noopener">OWASP GenAI Security Project crosswalk</a>${data.meta.version ? " (v" + esc(data.meta.version) + ")" : ""}, used under <a href="https://creativecommons.org/licenses/by-sa/4.0/" target="_blank" rel="noopener">CC BY-SA 4.0</a>. This adaptation is shared under the same license.
      </div>

      <div class="cw-bar">
        <span class="cw-seg" id="cwMode">
          <button data-m="risk" class="on">By Risk</button>
          <button data-m="framework">By Framework</button>
          <button data-m="matrix">Matrix</button>
        </span>
        <input class="cw-search" id="cwSearch" placeholder="Search risks or controls" autocomplete="off" spellcheck="false">
        <button class="cw-export" id="cwExport">Export CSV</button>
      </div>

      <div class="cw-filters" id="cwFilters"></div>

      <div class="cw-cols" id="cwCols">
        <div class="cw-list" id="cwList"></div>
        <div class="cw-detail" id="cwDetail"></div>
      </div>

      <div class="cw-matrix" id="cwMatrix"></div>
    </div>`;

  const $ = (s) => main.querySelector(s);
  const listEl = $("#cwList"), detailEl = $("#cwDetail"), filtersEl = $("#cwFilters");
  const searchEl = $("#cwSearch");
  const colsEl = $("#cwCols"), matrixEl = $("#cwMatrix");

  // Toggle between the list/detail layout and the full-width matrix view.
  function applyMode() {
    const mx = state.mode === "matrix";
    colsEl.style.display = mx ? "none" : "";
    matrixEl.classList.toggle("on", mx);
  }

  // ---- filters UI (rebuilt per mode) ----
  function drawFilters() {
    if (state.mode === "risk") {
      const listChips = (data.meta.lists || []).map((l) => {
        const meta = LIST_META[l.id] || {};
        return `<button class="cw-chip list ${state.lists.has(l.id) ? "on" : ""}" data-list="${esc(l.id)}"><span class="cw-dot" style="--c:${meta.color || "var(--mut)"}"></span>${esc(l.label)} <span style="color:var(--mut)">${l.count}</span></button>`;
      }).join("");
      const sevChips = ["Critical", "High", "Medium", "Low"].map((s) =>
        `<button class="cw-chip sev ${state.sevs.has(s) ? "on" : ""}" data-sev="${s}"><span class="cw-dot" style="--c:${sevColor(s)}"></span>${s}</button>`).join("");
      const fwOpts = `<option value="">All frameworks</option>` + frameworks.map((f) => `<option value="${esc(f.name)}" ${state.fw === f.name ? "selected" : ""}>${esc(f.name)}</option>`).join("");
      filtersEl.innerHTML = `<span class="cw-flabel">List</span>${listChips}<span class="cw-flabel" style="margin-left:6px">Severity</span>${sevChips}<select class="cw-sel" id="cwFwFilter" style="margin-left:6px">${fwOpts}</select>`;
      filtersEl.querySelectorAll("[data-list]").forEach((b) => b.onclick = () => { toggle(state.lists, b.dataset.list); drawFilters(); drawList(); });
      filtersEl.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { toggle(state.sevs, b.dataset.sev); drawFilters(); drawList(); });
      $("#cwFwFilter").onchange = (e) => { state.fw = e.target.value; drawList(); if (state.selRisk) drawDetail(); };
    } else if (state.mode === "matrix") {
      const listChips = (data.meta.lists || []).map((l) => {
        const meta = LIST_META[l.id] || {};
        return `<button class="cw-chip list ${state.lists.has(l.id) ? "on" : ""}" data-list="${esc(l.id)}"><span class="cw-dot" style="--c:${meta.color || "var(--mut)"}"></span>${esc(l.label)} <span style="color:var(--mut)">${l.count}</span></button>`;
      }).join("");
      const sevChips = ["Critical", "High", "Medium", "Low"].map((s) =>
        `<button class="cw-chip sev ${state.sevs.has(s) ? "on" : ""}" data-sev="${s}"><span class="cw-dot" style="--c:${sevColor(s)}"></span>${s}</button>`).join("");
      filtersEl.innerHTML = `<span class="cw-flabel">List</span>${listChips}<span class="cw-flabel" style="margin-left:6px">Severity</span>${sevChips}`;
      filtersEl.querySelectorAll("[data-list]").forEach((b) => b.onclick = () => { toggle(state.lists, b.dataset.list); drawFilters(); drawMatrix(); });
      filtersEl.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { toggle(state.sevs, b.dataset.sev); drawFilters(); drawMatrix(); });
    } else {
      filtersEl.innerHTML = `<span class="cw-flabel">Severity</span>` + ["Critical", "High", "Medium", "Low"].map((s) =>
        `<button class="cw-chip sev ${state.sevs.has(s) ? "on" : ""}" data-sev="${s}"><span class="cw-dot" style="--c:${sevColor(s)}"></span>${s}</button>`).join("");
      filtersEl.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { toggle(state.sevs, b.dataset.sev); drawFilters(); if (state.selFw) drawDetail(); });
    }
  }
  function toggle(set, v) { set.has(v) ? set.delete(v) : set.add(v); }

  // ---- risk list ----
  function riskMatches(r) {
    if (state.lists.size && !state.lists.has(r.list)) return false;
    if (state.sevs.size && !state.sevs.has(r.sev)) return false;
    if (state.fw && !r.maps.some((m) => m.f === state.fw)) return false;
    if (state.q) {
      const q = state.q;
      const inMaps = r.maps.some((m) => (m.n && m.n.toLowerCase().includes(q)) || (m.c && m.c.toLowerCase().includes(q)) || (m.f && m.f.toLowerCase().includes(q)));
      if (!(r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q) || inMaps)) return false;
    }
    return true;
  }

  function drawList() {
    if (state.mode === "risk") {
      const matched = risks.filter(riskMatches);
      if (!matched.length) { listEl.innerHTML = `<div class="cw-empty">No risks match your filters.</div>`; return; }
      const byList = {};
      matched.forEach((r) => { (byList[r.list] = byList[r.list] || []).push(r); });
      let html = "";
      (data.meta.lists || []).forEach((l) => {
        const rs = byList[l.id]; if (!rs) return;
        html += `<div class="cw-grp">${esc(l.label)} · ${rs.length}</div>`;
        html += rs.map((r) => {
          const meta = LIST_META[r.list] || {};
          const shown = state.fw ? r.maps.filter((m) => m.f === state.fw).length : r.maps.length;
          return `<div class="cw-item ${state.selRisk === r.id ? "on" : ""}" data-risk="${esc(r.id)}">
            <span class="cw-id" style="--c:${meta.color || "var(--acc)"}">${esc(r.id)}</span>
            <span class="cw-nm" title="${esc(r.name)}">${esc(r.name)}</span>
            <span class="cw-sev" style="--c:${sevColor(r.sev)}" title="${esc(r.sev)}"></span>
            <span class="cw-cnt">${shown}</span>
          </div>`;
        }).join("");
      });
      listEl.innerHTML = html;
      listEl.querySelectorAll("[data-risk]").forEach((el) => el.onclick = () => { state.selRisk = el.dataset.risk; drawList(); drawDetail(); });
    } else {
      const q = state.q;
      const fws = frameworks.filter((f) => !q || f.name.toLowerCase().includes(q) || (fwIndex.get(f.name) || []).some((x) => (x.map.n && x.map.n.toLowerCase().includes(q)) || (x.map.c && x.map.c.toLowerCase().includes(q))));
      if (!fws.length) { listEl.innerHTML = `<div class="cw-empty">No frameworks match.</div>`; return; }
      listEl.innerHTML = `<div class="cw-grp">Frameworks · ${fws.length}</div>` + fws.map((f) => {
        const rows = fwIndex.get(f.name) || [];
        return `<div class="cw-item ${state.selFw === f.name ? "on" : ""}" data-fw="${esc(f.name)}">
          <span class="cw-nm" title="${esc(f.name)}">${esc(f.name)}</span>
          <span class="cw-cnt">${rows.length}</span>
        </div>`;
      }).join("");
      listEl.querySelectorAll("[data-fw]").forEach((el) => el.onclick = () => { state.selFw = el.dataset.fw; drawList(); drawDetail(); });
    }
  }

  // ---- detail ----
  function drawDetail() {
    if (state.mode === "risk") {
      const r = risks.find((x) => x.id === state.selRisk);
      if (!r) { detailEl.innerHTML = `<div class="cw-empty">Select a risk to see its framework coverage.</div>`; return; }
      const meta = LIST_META[r.list] || {};
      const listLabel = (data.meta.lists.find((l) => l.id === r.list) || {}).label || r.list;
      // group mappings by framework
      let maps = r.maps.slice();
      if (state.fw) maps = maps.filter((m) => m.f === state.fw);
      const byFw = new Map();
      maps.forEach((m) => { if (!byFw.has(m.f)) byFw.set(m.f, []); byFw.get(m.f).push(m); });
      const fwOrder = [...byFw.keys()].sort();
      const aud = (r.aud || []).map((a) => `<span class="cw-b">${esc(a)}</span>`).join("");
      detailEl.innerHTML = `
        <div class="cw-dhead">
          <h2><span class="cw-id" style="--c:${meta.color || "var(--acc)"}">${esc(r.id)}</span>${esc(r.name)}</h2>
          <div class="cw-badges">
            <span class="cw-b sev" style="--c:${sevColor(r.sev)}">${esc(r.sev)}</span>
            <span class="cw-b">${esc(listLabel)}</span>
            ${r.aivss != null ? `<span class="cw-b">AIVSS ${esc(r.aivss)}</span>` : ""}
            ${r.ver ? `<span class="cw-b">${esc(r.ver)}</span>` : ""}
            <span class="cw-b">${maps.length} mapping${maps.length === 1 ? "" : "s"} · ${fwOrder.length} framework${fwOrder.length === 1 ? "" : "s"}</span>
            ${fwOrder.length > 1 ? xallBtn() : ""}
          </div>
          ${aud ? `<div class="cw-badges" style="margin-top:7px">${aud}</div>` : ""}
        </div>
        <div class="cw-dbody">${fwOrder.map((f) => fwBlock(f, byFw.get(f), fwOrder.length === 1)).join("") || `<div class="cw-empty">No mappings for this filter.</div>`}</div>`;
      wireFwBlocks();
    } else {
      const f = state.selFw;
      if (!f) { detailEl.innerHTML = `<div class="cw-empty">Select a framework.</div>`; return; }
      let rows = (fwIndex.get(f) || []);
      if (state.sevs.size) rows = rows.filter((x) => state.sevs.has(x.risk.sev));
      // group by risk
      const byRisk = new Map();
      rows.forEach((x) => { if (!byRisk.has(x.risk.id)) byRisk.set(x.risk.id, { risk: x.risk, maps: [] }); byRisk.get(x.risk.id).maps.push(x.map); });
      const groups = [...byRisk.values()].sort((a, b) => (SEV_RANK[a.risk.sev] ?? 9) - (SEV_RANK[b.risk.sev] ?? 9));
      detailEl.innerHTML = `
        <div class="cw-dhead">
          <h2>${esc(f)}</h2>
          <div class="cw-badges">
            ${fwVer[f] ? `<span class="cw-b">${esc(fwVer[f])}</span>` : ""}
            <span class="cw-b">${rows.length} mapping${rows.length === 1 ? "" : "s"} · ${groups.length} risk${groups.length === 1 ? "" : "s"}</span>
            ${fwUrl[f] ? `<a class="cw-link" href="${esc(fwUrl[f])}" target="_blank" rel="noopener">Source ↗</a>` : ""}
            ${groups.length > 1 ? xallBtn() : ""}
          </div>
        </div>
        <div class="cw-dbody">${groups.map((g) => riskBlock(g, groups.length === 1)).join("") || `<div class="cw-empty">No risks for this filter.</div>`}</div>`;
      wireFwBlocks();
    }
  }

  function ctrlRow(m) {
    const tags = [];
    if (m.t) tags.push(`<span class="cw-tag">${esc(m.t)}</span>`);
    if (m.s) tags.push(`<span class="cw-tag">${esc(m.s)}</span>`);
    return `<div class="cw-ctrl"><span class="cw-cid">${esc(m.c || "—")}</span><span class="cw-cn">${esc(m.n || "")}</span><span class="cw-meta">${tags.join("")}</span></div>`;
  }
  function fwBlock(f, maps, open) {
    return `<div class="cw-fw${open ? " open" : ""}"><div class="cw-fwh"><span class="cw-caret">▶</span><span class="cw-fwn">${esc(f)}</span>${fwVer[f] ? `<span class="cw-fwv">${esc(fwVer[f])}</span>` : ""}<span class="cw-pill">${maps.length}</span>${fwUrl[f] ? `<a class="cw-link" href="${esc(fwUrl[f])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">↗</a>` : ""}</div><div class="cw-ctrls">${maps.map(ctrlRow).join("")}</div></div>`;
  }
  function riskBlock(g, open) {
    const meta = LIST_META[g.risk.list] || {};
    return `<div class="cw-fw${open ? " open" : ""}"><div class="cw-fwh"><span class="cw-caret">▶</span><span class="cw-id" style="--c:${meta.color || "var(--acc)"}">${esc(g.risk.id)}</span><span class="cw-fwn">${esc(g.risk.name)}</span><span class="cw-sev" style="--c:${sevColor(g.risk.sev)}"></span><span class="cw-pill">${g.maps.length}</span></div><div class="cw-ctrls">${g.maps.map(ctrlRow).join("")}</div></div>`;
  }
  // Sections start collapsed (each header shows its control count) so one risk is not a page of ~100 rows.
  function xallBtn() { return `<button type="button" class="cw-xall" id="cwXall">Expand all</button>`; }
  function wireFwBlocks() {
    detailEl.querySelectorAll(".cw-fwh").forEach((h) => h.onclick = () => h.parentElement.classList.toggle("open"));
    const x = detailEl.querySelector("#cwXall");
    if (x) x.onclick = () => {
      const open = x.textContent === "Expand all";
      detailEl.querySelectorAll(".cw-fw").forEach((b) => b.classList.toggle("open", open));
      x.textContent = open ? "Collapse all" : "Expand all";
    };
  }

  // ---- matrix / heatmap + coverage-gap analysis ----
  // Rows respect the list/severity/search filters; the framework columns are fixed.
  function matrixRisks() {
    return risks.filter((r) => {
      if (state.lists.size && !state.lists.has(r.list)) return false;
      if (state.sevs.size && !state.sevs.has(r.sev)) return false;
      if (state.q && !(r.name.toLowerCase().includes(state.q) || r.id.toLowerCase().includes(state.q))) return false;
      return true;
    });
  }
  // Discrete heatmap shade: graduated alpha on the accent hue; 0 is handled separately (hatched).
  function cellFill(n, max) {
    const ratio = max > 0 ? n / max : 0;
    const a = (0.16 + 0.64 * ratio).toFixed(3);
    return `rgba(37,99,235,${a})`;
  }

  function drawMatrix() {
    const rows = matrixRisks();
    const mx = buildMatrix(rows, frameworks);
    const head = `<thead><tr>
        <th class="cw-corner">Risk \\ Framework</th>
        ${frameworks.map((f) => `<th title="${esc(f.name)}${f.ver ? " · " + f.ver : ""}">${fwUrl[f.name] ? `<a href="${esc(fwUrl[f.name])}" target="_blank" rel="noopener">${esc(f.name)}</a>` : esc(f.name)}</th>`).join("")}
      </tr></thead>`;
    const byList = {};
    rows.forEach((r) => { (byList[r.list] = byList[r.list] || []).push(r); });
    let body = "";
    (data.meta.lists || []).forEach((l) => {
      const rs = byList[l.id]; if (!rs) return;
      const meta = LIST_META[l.id] || {};
      body += `<tr class="cw-grprow"><th colspan="${frameworks.length + 1}">${esc(l.label)} · ${rs.length}</th></tr>`;
      body += rs.map((r) => {
        const row = mx.counts[r.id];
        const cells = frameworks.map((f) => {
          const n = row[f.name] || 0;
          if (!n) return `<td class="cw-mc z" title="${esc(r.id)} · ${esc(f.name)}: no mapping">·</td>`;
          return `<td class="cw-mc cell" data-risk="${esc(r.id)}" data-fw="${esc(f.name)}" style="--c:${cellFill(n, mx.maxCell)}" title="${esc(r.id)} · ${esc(f.name)}: ${n} mapping${n === 1 ? "" : "s"}">${n}</td>`;
        }).join("");
        return `<tr><th class="cw-rowh"><span class="cw-rwrap"><span class="cw-id" style="--c:${meta.color || "var(--acc)"}">${esc(r.id)}</span><span class="cw-sev" style="--c:${sevColor(r.sev)}" title="${esc(r.sev)}"></span><span class="cw-nm" title="${esc(r.name)}">${esc(r.name)}</span></span></th>${cells}</tr>`;
      }).join("");
    });

    if (!rows.length) {
      matrixEl.innerHTML = `<div class="cw-mwrap"><div class="cw-gapfull">No risks match your filters.</div></div>`;
      return;
    }

    matrixEl.innerHTML = `
      <div class="cw-mwrap"><table class="cw-m">${head}<tbody>${body}</tbody></table></div>
      <div class="cw-mlegend"><span>Control mappings per cell:</span><span class="cw-sw z"></span><span>0 (uncovered)</span>${[1, 2, 3].map((k) => `<span class="cw-sw" style="--c:${cellFill(k, 3)}"></span>`).join("")}<span>more</span><span style="margin-left:4px">Click a cell to open that risk filtered to that framework.</span></div>
      ${gapPanel(rows)}`;

    matrixEl.querySelectorAll("td.cw-mc.cell").forEach((td) => td.onclick = () => {
      state.fw = td.dataset.fw;
      state.selRisk = td.dataset.risk;
      setMode("risk");
    });
    const gfw = matrixEl.querySelector("#cwGapFw");
    if (gfw) gfw.onchange = (e) => { state.gapFw = e.target.value; drawMatrix(); };
    const gx = matrixEl.querySelector("#cwGapExport");
    if (gx) gx.onclick = exportGapsCsv;
  }

  function gapPanel(rows) {
    if (!state.gapFw || !frameworks.some((f) => f.name === state.gapFw)) state.gapFw = frameworks[0] ? frameworks[0].name : null;
    const fw = state.gapFw;
    const gaps = coverageGaps(rows, fw);
    const M = rows.length;
    const fwOpts = frameworks.map((f) => `<option value="${esc(f.name)}" ${fw === f.name ? "selected" : ""}>${esc(f.name)}</option>`).join("");
    const body = gaps.length
      ? gaps.map((r) => {
          const meta = LIST_META[r.list] || {};
          const k = coverageBreadth(r);
          const thin = k <= 3 ? " thin" : "";
          return `<div class="cw-grisk">
            <span class="cw-id" style="--c:${meta.color || "var(--acc)"}">${esc(r.id)}</span>
            <span class="cw-nm" title="${esc(r.name)}">${esc(r.name)}</span>
            <span class="cw-b sev" style="--c:${sevColor(r.sev)}">${esc(r.sev)}</span>
            <span class="cw-breadth${thin}" title="distinct frameworks mapping this risk">covered by ${k} of ${frameworks.length}</span>
          </div>`;
        }).join("")
      : `<div class="cw-gapfull">No gaps: every one of the ${M} shown risk${M === 1 ? " maps" : "s map"} to ${esc(fw)}.</div>`;
    return `<div class="cw-gap">
      <div class="cw-gaphead">
        <h3>Coverage gap analysis</h3>
        <select class="cw-sel cw-gfw" id="cwGapFw">${fwOpts}</select>
        <button class="cw-export cw-gapexp" id="cwGapExport">Export gaps CSV</button>
      </div>
      <div class="cw-gapline"><b>${gaps.length}</b> of <b>${M}</b> shown risk${M === 1 ? "" : "s"} have no mapping to <b>${esc(fw)}</b>.</div>
      <div class="cw-gapsub">Uncovered risks, Critical first. "covered by K of ${frameworks.length}" counts the distinct frameworks mapping each risk, so thinly-covered risks stand out.</div>
      <div class="cw-gaplist">${body}</div>
    </div>`;
  }

  // ---- CSV helpers ----
  function csvRows(rows) { return rows.map((r) => r.map((c) => `"${String(c == null ? "" : c).replace(/"/g, '""')}"`).join(",")).join("\r\n"); }
  function download(csv, filename, count, noun) {
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    try { window.showToast && window.showToast("Exported " + count + " " + noun, "ok"); } catch (_) {}
  }

  function exportMatrixCsv() {
    const rows = matrixRisks();
    const mx = buildMatrix(rows, frameworks);
    const out = [["risk_id", "risk_name", "severity", ...frameworks.map((f) => f.name)]];
    rows.forEach((r) => out.push([r.id, r.name, r.sev, ...frameworks.map((f) => mx.counts[r.id][f.name])]));
    download(csvRows(out), "crosswalk-matrix.csv", rows.length, "risk rows");
  }
  function exportGapsCsv() {
    const rows = matrixRisks();
    const fw = state.gapFw;
    const gaps = coverageGaps(rows, fw);
    const out = [["framework", "uncovered_risk_id", "risk_name", "severity"]];
    gaps.forEach((r) => out.push([fw, r.id, r.name, r.sev]));
    download(csvRows(out), "crosswalk-gaps-" + String(fw || "framework").replace(/[^\w-]+/g, "-") + ".csv", gaps.length, "uncovered risks");
  }

  // ---- export current view as CSV ----
  function exportCsv() {
    if (state.mode === "matrix") { exportMatrixCsv(); return; }
    const rows = [["risk_id", "risk_name", "source_list", "severity", "framework", "framework_version", "control_id", "control_name", "tier", "scope"]];
    const push = (r, m) => rows.push([r.id, r.name, r.list, r.sev, m.f, fwVer[m.f] || "", m.c, m.n, m.t, m.s]);
    if (state.mode === "risk") {
      const r = risks.find((x) => x.id === state.selRisk); if (!r) return;
      (state.fw ? r.maps.filter((m) => m.f === state.fw) : r.maps).forEach((m) => push(r, m));
    } else {
      let rws = fwIndex.get(state.selFw) || [];
      if (state.sevs.size) rws = rws.filter((x) => state.sevs.has(x.risk.sev));
      rws.forEach((x) => push(x.risk, x.map));
    }
    const csv = rows.map((r) => r.map((c) => `"${String(c == null ? "" : c).replace(/"/g, '""')}"`).join(",")).join("\r\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "crosswalk-" + (state.mode === "risk" ? (state.selRisk || "risk") : (state.selFw || "framework").replace(/[^\w-]+/g, "-")) + ".csv";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
    try { window.showToast && window.showToast("Exported " + (rows.length - 1) + " mappings", "ok"); } catch (_) {}
  }

  // ---- wire top controls ----
  function setMode(m) {
    state.mode = m;
    $("#cwMode").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x.dataset.m === m));
    searchEl.value = ""; state.q = "";
    applyMode();
    drawFilters();
    if (m === "matrix") drawMatrix();
    else { drawList(); drawDetail(); }
  }
  $("#cwMode").querySelectorAll("button").forEach((b) => b.onclick = () => setMode(b.dataset.m));
  searchEl.oninput = () => { state.q = searchEl.value.trim().toLowerCase(); if (state.mode === "matrix") drawMatrix(); else drawList(); };
  $("#cwExport").onclick = exportCsv;

  applyMode();
  drawFilters(); drawList(); drawDetail();
}
