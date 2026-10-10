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
.cw-detail{border:1px solid var(--line);border-radius:12px;background:var(--card);padding:0;min-height:300px;overflow:hidden}
.cw-dhead{padding:16px 20px;border-bottom:1px solid var(--line);background:var(--bg2,var(--card2,transparent))}
.cw-dhead h2{margin:0 0 6px;font-size:1.15rem;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.cw-badges{display:flex;gap:7px;flex-wrap:wrap;margin-top:6px}
.cw-b{font-size:.72rem;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mut)}
.cw-b.sev{color:#fff;border:0}
.cw-dbody{padding:6px 0}
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
@media(max-width:860px){.cw-cols{grid-template-columns:1fr}.cw-list{max-height:none}}
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
  const state = { mode: "risk", q: "", lists: new Set(), sevs: new Set(), fw: "", selRisk: risks[0] ? risks[0].id : null, selFw: frameworks[0] ? frameworks[0].name : null };

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
        </span>
        <input class="cw-search" id="cwSearch" placeholder="Search risks, frameworks, controls…" autocomplete="off" spellcheck="false">
        <button class="cw-export" id="cwExport">Export CSV</button>
      </div>

      <div class="cw-filters" id="cwFilters"></div>

      <div class="cw-cols">
        <div class="cw-list" id="cwList"></div>
        <div class="cw-detail" id="cwDetail"></div>
      </div>
    </div>`;

  const $ = (s) => main.querySelector(s);
  const listEl = $("#cwList"), detailEl = $("#cwDetail"), filtersEl = $("#cwFilters");
  const searchEl = $("#cwSearch");

  // ---- filters UI (rebuilt per mode) ----
  function drawFilters() {
    if (state.mode === "risk") {
      const listChips = (data.meta.lists || []).map((l) => {
        const meta = LIST_META[l.id] || {};
        return `<button class="cw-chip list ${state.lists.has(l.id) ? "on" : ""}" data-list="${esc(l.id)}"><span class="cw-dot" style="background:${meta.color || "var(--mut)"}"></span>${esc(l.label)} <span style="color:var(--mut)">${l.count}</span></button>`;
      }).join("");
      const sevChips = ["Critical", "High", "Medium", "Low"].map((s) =>
        `<button class="cw-chip sev ${state.sevs.has(s) ? "on" : ""}" data-sev="${s}"><span class="cw-dot" style="background:${sevColor(s)}"></span>${s}</button>`).join("");
      const fwOpts = `<option value="">All frameworks</option>` + frameworks.map((f) => `<option value="${esc(f.name)}" ${state.fw === f.name ? "selected" : ""}>${esc(f.name)}</option>`).join("");
      filtersEl.innerHTML = `<span class="cw-flabel">List</span>${listChips}<span class="cw-flabel" style="margin-left:6px">Severity</span>${sevChips}<select class="cw-sel" id="cwFwFilter" style="margin-left:6px">${fwOpts}</select>`;
      filtersEl.querySelectorAll("[data-list]").forEach((b) => b.onclick = () => { toggle(state.lists, b.dataset.list); drawFilters(); drawList(); });
      filtersEl.querySelectorAll("[data-sev]").forEach((b) => b.onclick = () => { toggle(state.sevs, b.dataset.sev); drawFilters(); drawList(); });
      $("#cwFwFilter").onchange = (e) => { state.fw = e.target.value; drawList(); if (state.selRisk) drawDetail(); };
    } else {
      filtersEl.innerHTML = `<span class="cw-flabel">Severity</span>` + ["Critical", "High", "Medium", "Low"].map((s) =>
        `<button class="cw-chip sev ${state.sevs.has(s) ? "on" : ""}" data-sev="${s}"><span class="cw-dot" style="background:${sevColor(s)}"></span>${s}</button>`).join("");
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
            <span class="cw-id" style="background:${meta.color || "var(--acc)"}">${esc(r.id)}</span>
            <span class="cw-nm" title="${esc(r.name)}">${esc(r.name)}</span>
            <span class="cw-sev" style="background:${sevColor(r.sev)}" title="${esc(r.sev)}"></span>
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
          <h2><span class="cw-id" style="background:${meta.color || "var(--acc)"}">${esc(r.id)}</span>${esc(r.name)}</h2>
          <div class="cw-badges">
            <span class="cw-b sev" style="background:${sevColor(r.sev)}">${esc(r.sev)}</span>
            <span class="cw-b">${esc(listLabel)}</span>
            ${r.aivss != null ? `<span class="cw-b">AIVSS ${esc(r.aivss)}</span>` : ""}
            ${r.ver ? `<span class="cw-b">${esc(r.ver)}</span>` : ""}
            <span class="cw-b">${maps.length} mapping${maps.length === 1 ? "" : "s"} · ${fwOrder.length} framework${fwOrder.length === 1 ? "" : "s"}</span>
          </div>
          ${aud ? `<div class="cw-badges" style="margin-top:7px">${aud}</div>` : ""}
        </div>
        <div class="cw-dbody">${fwOrder.map((f) => fwBlock(f, byFw.get(f))).join("") || `<div class="cw-empty">No mappings for this filter.</div>`}</div>`;
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
          </div>
        </div>
        <div class="cw-dbody">${groups.map((g) => riskBlock(g)).join("") || `<div class="cw-empty">No risks for this filter.</div>`}</div>`;
      wireFwBlocks();
    }
  }

  function ctrlRow(m) {
    const tags = [];
    if (m.t) tags.push(`<span class="cw-tag">${esc(m.t)}</span>`);
    if (m.s) tags.push(`<span class="cw-tag">${esc(m.s)}</span>`);
    return `<div class="cw-ctrl"><span class="cw-cid">${esc(m.c || "—")}</span><span class="cw-cn">${esc(m.n || "")}</span><span class="cw-meta">${tags.join("")}</span></div>`;
  }
  function fwBlock(f, maps) {
    return `<div class="cw-fw open"><div class="cw-fwh"><span class="cw-caret">▶</span><span class="cw-fwn">${esc(f)}</span>${fwVer[f] ? `<span class="cw-fwv">${esc(fwVer[f])}</span>` : ""}<span class="cw-pill">${maps.length}</span>${fwUrl[f] ? `<a class="cw-link" href="${esc(fwUrl[f])}" target="_blank" rel="noopener" onclick="event.stopPropagation()">↗</a>` : ""}</div><div class="cw-ctrls">${maps.map(ctrlRow).join("")}</div></div>`;
  }
  function riskBlock(g) {
    const meta = LIST_META[g.risk.list] || {};
    return `<div class="cw-fw open"><div class="cw-fwh"><span class="cw-caret">▶</span><span class="cw-id" style="background:${meta.color || "var(--acc)"}">${esc(g.risk.id)}</span><span class="cw-fwn">${esc(g.risk.name)}</span><span class="cw-sev" style="background:${sevColor(g.risk.sev)}"></span><span class="cw-pill">${g.maps.length}</span></div><div class="cw-ctrls">${g.maps.map(ctrlRow).join("")}</div></div>`;
  }
  function wireFwBlocks() {
    detailEl.querySelectorAll(".cw-fwh").forEach((h) => h.onclick = () => h.parentElement.classList.toggle("open"));
  }

  // ---- export current view as CSV ----
  function exportCsv() {
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
  $("#cwMode").querySelectorAll("button").forEach((b) => b.onclick = () => {
    state.mode = b.dataset.m;
    $("#cwMode").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b));
    searchEl.value = ""; state.q = "";
    drawFilters(); drawList(); drawDetail();
  });
  searchEl.oninput = () => { state.q = searchEl.value.trim().toLowerCase(); drawList(); };
  $("#cwExport").onclick = exportCsv;

  drawFilters(); drawList(); drawDetail();
}
