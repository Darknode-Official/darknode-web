// Correlations scene (Deck D3): cross-tool attack chains. One tool sees "no MFA",
// another sees "impossible travel" on the SAME resolved person — together that is an
// account-takeover risk no single tool reports. Reads the Security Graph through the
// correlation engine (core/correlate.js) and lists each hit with the findings that
// make it up. Read-only — it never writes to the graph.
import { correlate, RULES } from "../core/correlate.js";

const S = { ctx: null, el: null, q: "", open: {} };

const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

function injectStyle() {
  if (document.getElementById("cor-css")) return;
  const st = document.createElement("style"); st.id = "cor-css";
  st.textContent = `
.cor-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 14px;line-height:1.5}
.cor-card{border:1px solid rgba(23,33,56,.12);border-radius:10px;padding:0;margin:0 0 10px;overflow:hidden}
.cor-head{display:flex;align-items:center;gap:10px;padding:12px 14px;cursor:pointer;background:#fff}
.cor-head:hover{background:rgba(23,33,56,.02)}
.cor-sev{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;border-radius:20px;padding:2px 9px;white-space:nowrap}
.cor-sev.critical{background:rgba(198,40,40,.12);color:#c62828}
.cor-sev.high{background:rgba(245,146,11,.14);color:#9a5a00}
.cor-sev.medium{background:rgba(37,82,198,.1);color:#2552c6}
.cor-sev.low,.cor-sev.info{background:rgba(23,33,56,.08);color:#45506a}
.cor-ttl{font-weight:650;font-size:13.5px;color:#141c2e}
.cor-subj{color:#5a6680;font-size:12px}
.cor-subj b{color:#141c2e;font-weight:650}
.cor-att{display:inline-block;font-size:10px;font-weight:700;background:rgba(23,33,56,.06);color:#45506a;border-radius:4px;padding:1px 6px;margin-left:6px;font-variant-numeric:tabular-nums}
.cor-chev{margin-left:auto;color:#9aa3b5;transition:transform .12s}
.cor-card.on .cor-chev{transform:rotate(90deg)}
.cor-body{padding:2px 14px 14px;border-top:1px solid rgba(23,33,56,.08);display:none}
.cor-card.on .cor-body{display:block}
.cor-exp{color:#45506a;font-size:12.5px;line-height:1.55;margin:10px 0 12px}
.cor-leg{display:flex;gap:9px;align-items:flex-start;padding:7px 0;border-top:1px dashed rgba(23,33,56,.09)}
.cor-leg:first-of-type{border-top:0}
.cor-leglbl{font-size:12px;color:#5a6680;min-width:230px}
.cor-finding{appearance:none;border:0;background:none;font:inherit;color:var(--dk-acc,#2552c6);font-weight:600;cursor:pointer;padding:0;text-align:left}
.cor-finding:hover{text-decoration:underline}
`;
  document.head.appendChild(st);
}

export function mountCorrelations(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el;
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>Correlations</h1><p>Attack chains your tools only see together — the same host or person flagged by two different tools adds up to a risk neither reports alone. Every chain links back to the findings that prove it.</p></div></div>
    <div class="dk-ovp">
      <p class="cor-sub">Deterministic rules over the resolved inventory (${RULES.length} rules). Nothing here is written back to the graph; these are a live read of the findings you already have.</p>
      <div class="dk-invbar"><div class="dk-isearch">${(ctx && ctx.IC_SEARCH) || ""}<input id="corQ" placeholder="Search correlations" value="${E(S.q)}" autocomplete="off" spellcheck="false"></div></div>
      <div id="corBody"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
    </div>`;
  let qT = 0; el.querySelector("#corQ").oninput = (e) => { clearTimeout(qT); qT = setTimeout(() => { S.q = e.target.value; refresh(); }, 150); };
  refresh();
}

function refresh() { if (S.ctx && S.el && S.el.isConnected && !S.el.hidden) S.ctx.withGraph(repaintCorrelations); }

export function repaintCorrelations(m) {
  if (!S.el || !S.el.isConnected || !S.ctx) return;
  const ents = m && m.listEntities ? m.listEntities() : [];
  let hits = correlate(ents, { now: Date.now() });
  const q = S.q.trim().toLowerCase();
  if (q) hits = hits.filter((h) => (h.title + " " + h.subjectName + " " + h.attack.join(" ")).toLowerCase().includes(q));
  const box = S.el.querySelector("#corBody"); if (!box) return;
  if (!hits.length) {
    box.innerHTML = `<div class="dk-nempty">No correlated attack chains${q ? " match" : " yet"}. Chains appear when two different tools flag the same resolved host or identity — for example run Conditional Access and VPN/Sign-in Forensics, then import a vulnerability scan alongside Attack Surface.</div>`;
    return;
  }
  box.innerHTML = hits.map((h, i) => {
    const on = S.open[h.ruleId + "|" + h.subjectKey];
    const legs = h.legs.map((l) => `<div class="cor-leg"><span class="cor-leglbl">${E(l.label)}</span><button class="cor-finding" data-fid="${E(l.findingId)}">${E(l.findingTitle)}</button></div>`).join("");
    return `<div class="cor-card${on ? " on" : ""}" data-key="${E(h.ruleId + "|" + h.subjectKey)}">
      <div class="cor-head">
        <span class="cor-sev ${E(h.severity)}">${E(SEV_LABEL[h.severity] || h.severity)}</span>
        <span><span class="cor-ttl">${E(h.title)}</span>${h.attack.map((a) => `<span class="cor-att">${E(a)}</span>`).join("")}<br><span class="cor-subj">on <b>${E(h.subjectName)}</b> · ${h.subjectType === "asset" ? "host" : "identity"}</span></span>
        <span class="cor-chev">›</span>
      </div>
      <div class="cor-body"><p class="cor-exp">${E(h.explanation)}</p>${legs}</div>
    </div>`;
  }).join("");
  box.querySelectorAll(".cor-head").forEach((head) => head.onclick = (e) => {
    if (e.target.closest(".cor-finding")) return;
    const card = head.closest(".cor-card"), k = card.dataset.key;
    S.open[k] = !S.open[k]; card.classList.toggle("on", S.open[k]);
  });
  box.querySelectorAll(".cor-finding").forEach((b) => b.onclick = () => S.ctx.openEntityDrawer && S.ctx.openEntityDrawer(b.dataset.fid));
}
