// Asset Inventory scene (Deck D2): one deduplicated view of every host and identity
// the tools have recorded, plus a coverage matrix showing which control sources saw
// each one. Reads the Security Graph through the resolution layer (core/resolve.js);
// it never writes, so it cannot change the graph.
import { resolveAssets, resolveIdentities, coverageMatrix } from "../core/resolve.js";
// Control-area definitions (which tools cover each area) and the deterministic
// gap-finding generator both live in core/coverage.js, so the matrix columns and
// the published findings share one source of truth. ASSET_COV/IDENTITY_COV keep the
// { id, label, sources } the matrix needs, plus the severity/refs the findings need.
import { ASSET_COV, IDENTITY_COV, coverageFindings } from "../core/coverage.js";

const TABS = ["assets", "identities", "coverage"];
const TAB_LABEL = { assets: "Assets", identities: "Identities", coverage: "Coverage" };
const LS_TAB = "dn_deck_invtab";

const S = { ctx: null, el: null, tab: "assets", q: "" };

const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const lsGet = (k) => { try { return localStorage.getItem(k); } catch (_) { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} };

function injectStyle() {
  if (document.getElementById("inv-css")) return;
  const st = document.createElement("style"); st.id = "inv-css";
  st.textContent = `
.inv-tabs{display:flex;gap:2px;border-bottom:1px solid rgba(23,33,56,.1);margin:0 0 12px}
.inv-tab{appearance:none;border:0;background:none;font:inherit;font-size:12.5px;font-weight:600;color:#5a6680;padding:9px 14px 10px;border-bottom:2px solid transparent;margin-bottom:-1px;cursor:pointer;display:inline-flex;align-items:center;gap:7px}
.inv-tab:hover{color:#141c2e}
.inv-tab.on{color:var(--dk-acc,#2552c6);border-bottom-color:var(--dk-acc,#2552c6)}
.inv-tab .n{font-size:11px;font-weight:700;font-variant-numeric:tabular-nums;background:rgba(23,33,56,.07);color:#5a6680;border-radius:20px;padding:1px 7px}
.inv-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 12px;line-height:1.5}
.inv-cell.yes{color:#12a85f;font-weight:700}
.inv-cell.no{color:#c62828;font-weight:700}
.inv-src{display:inline-block;font-size:10.5px;background:rgba(23,33,56,.06);color:#45506a;border-radius:20px;padding:1px 8px;margin:1px 3px 1px 0;white-space:nowrap}
.inv-open{appearance:none;border:0;background:none;font:inherit;color:var(--dk-acc,#2552c6);font-weight:600;cursor:pointer;padding:0;text-align:left}
#invBody .dk-itable td:first-child{min-width:150px} /* host/identity names stay readable on a phone; the table scrolls instead */
.inv-open:hover{text-decoration:underline}
.inv-sug{font-size:12px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:8px 11px;margin:10px 0 0}
.inv-covbar{display:flex;gap:14px;align-items:center;justify-content:space-between;flex-wrap:wrap;border:1px solid rgba(37,82,198,.22);background:rgba(37,82,198,.04);border-radius:10px;padding:11px 14px;margin:0 0 16px}
.inv-covtxt{font-size:12.5px;color:#45506a;line-height:1.5;max-width:720px}
.inv-covtxt b{color:#141c2e}
.inv-covbtn{appearance:none;border:1px solid rgba(37,82,198,.3);background:rgba(37,82,198,.08);color:#2552c6;font:inherit;font-size:12.5px;font-weight:600;border-radius:6px;padding:7px 14px;cursor:pointer;white-space:nowrap}
.inv-covbtn:hover:not(:disabled){background:rgba(37,82,198,.14)}
.inv-covbtn:disabled{opacity:.45;cursor:default}
`;
  document.head.appendChild(st);
}

export function mountInventory(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el;
  const t = lsGet(LS_TAB); S.tab = TABS.includes(t) ? t : "assets";
  const IC = (ctx && ctx.IC) || {};
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>Asset Inventory</h1><p>One deduplicated view of every host and identity your tools have recorded — the same machine or person seen by several tools shown once — and which control sources cover each.</p></div></div>
    <div class="dk-ovp">
      <div class="inv-tabs" id="invTabs" role="tablist"></div>
      <div class="dk-invbar"><div class="dk-isearch">${(ctx && ctx.IC_SEARCH) || ""}<input id="invQ" aria-label="Search inventory" placeholder="Search inventory" value="${E(S.q)}" autocomplete="off" spellcheck="false"></div></div>
      <div id="invBody"><div class="dk-loading"><span class="sp"></span>Reading the security graph…</div></div>
    </div>`;
  const $ = (s) => el.querySelector(s);
  $("#invTabs").onclick = (e) => { const b = e.target.closest("[data-tab]"); if (b) { S.tab = b.dataset.tab; lsSet(LS_TAB, S.tab); refresh(); } };
  let qT = 0; $("#invQ").oninput = (e) => { clearTimeout(qT); qT = setTimeout(() => { S.q = e.target.value; refresh(); }, 150); };
  refresh();
}

function refresh() { if (S.ctx && S.el && S.el.isConnected && !S.el.hidden) S.ctx.withGraph(repaintInventory); }

export function repaintInventory(m) {
  if (!S.el || !S.el.isConnected || !S.ctx) return;
  const ents = m && m.listEntities ? m.listEntities() : [];
  const assets = resolveAssets(ents);
  const idRes = resolveIdentities(ents);
  const tabs = S.el.querySelector("#invTabs");
  if (tabs) tabs.innerHTML = TABS.map((t) => {
    const n = t === "assets" ? assets.length : t === "identities" ? idRes.clusters.length : assets.length + idRes.clusters.length;
    return `<button class="inv-tab${t === S.tab ? " on" : ""}" role="tab" data-tab="${t}">${E(TAB_LABEL[t])}<span class="n">${n.toLocaleString()}</span></button>`;
  }).join("");
  const box = S.el.querySelector("#invBody"); if (!box) return;
  const q = S.q.trim().toLowerCase();
  const matchAsset = (c) => !q || c.name.toLowerCase().includes(q) || c.ips.some((i) => i.includes(q)) || c.sources.some((s) => s.includes(q));
  const matchId = (c) => !q || c.name.toLowerCase().includes(q) || c.emails.some((e) => e.includes(q)) || c.sources.some((s) => s.includes(q));
  if (S.tab === "assets") box.innerHTML = assetTable(assets.filter(matchAsset));
  else if (S.tab === "identities") box.innerHTML = idTable(idRes.clusters.filter(matchId), idRes.suggestions);
  else {
    // Publishing uses the FULL resolved inventory, never the search-filtered subset,
    // so a search never causes the sink to auto-resolve findings for hidden rows.
    S.allAssets = assets; S.allIds = idRes.clusters;
    // Open coverage findings already in the queue: publishing re-checks them, so the button
    // stays usable to close fixed gaps even when no new gap is left.
    const openCov = ents.filter((e) => e && e.type === "FINDING" && e.data && e.data.tool === "coverage" && !["resolved", "closed"].includes(e.status)).length;
    box.innerHTML = coverageView(assets.filter(matchAsset), idRes.clusters.filter(matchId), coverageFindings(assets, idRes.clusters).length, openCov);
  }
  box.querySelectorAll("[data-open]").forEach((b) => b.onclick = () => S.ctx.openEntityDrawer && S.ctx.openEntityDrawer(b.dataset.open));
  const covBtn = box.querySelector("#invCovCreate");
  if (covBtn) covBtn.onclick = async () => {
    if (covBtn.disabled) return;
    const findings = coverageFindings(S.allAssets || [], S.allIds || []);
    const toast = S.ctx && S.ctx.toast;
    covBtn.disabled = true; const prev = covBtn.textContent; covBtn.textContent = "Publishing…";
    let res = null;
    try { const sink = await import("/js/core/sink.js"); res = await sink.publishFindings("coverage", findings, { dataset: "Inventory coverage", quiet: true }); } catch (_) { res = null; }
    covBtn.textContent = prev;
    if (!res) { covBtn.disabled = false; if (toast) toast("Could not publish coverage findings", "error"); return; }
    if (toast && findings.length) toast(`${res.created} added, ${res.updated} updated in the Findings queue`, "success");
    else if (toast && !res.fixed) toast("No coverage finding was closed", "info"); // a fixed one toasts from the sink
    refresh();                                       // reflect the new graph state
  };
}

const srcChips = (sources) => sources.map((s) => `<span class="inv-src">${E(s)}</span>`).join("") || `<span class="dk-mut">—</span>`;
const openCell = (c) => `<button class="inv-open" data-open="${E(c.members[0])}">${E(c.name)}</button>${c.members.length > 1 ? ` <span class="dk-mut">(${c.members.length} records)</span>` : ""}`;

function assetTable(rows) {
  if (!rows.length) return `<div class="dk-nempty">No hosts match. Run a scan (Attack Surface, Vulnerability Import, Fleet Compliance) to populate the inventory.</div>`;
  return `<p class="inv-sub">${rows.length.toLocaleString()} host${rows.length === 1 ? "" : "s"}. Variants (case, short name vs FQDN, shared MAC) are merged into one row; ambiguous short names are kept separate.</p>
  <div class="dk-itwrap"><table class="dk-itable"><thead><tr><th>Host</th><th>Type</th><th>IP addresses</th><th>Seen by</th></tr></thead><tbody>${rows.map((c) => `<tr><td>${openCell(c)}</td><td>${E(c.type)}</td><td>${c.ips.length ? c.ips.map((i) => E(i)).join("<br>") : '<span class="dk-mut">—</span>'}</td><td>${srcChips(c.sources)}</td></tr>`).join("")}</tbody></table></div>`;
}

function idTable(rows, suggestions) {
  const sug = (suggestions || []).length ? `<div class="inv-sug">${suggestions.length} possible duplicate${suggestions.length === 1 ? "" : "s"} by name (different email addresses — not merged automatically): ${suggestions.slice(0, 8).map((s) => E(s.nameKey)).join(", ")}${suggestions.length > 8 ? "…" : ""}</div>` : "";
  if (!rows.length) return `<div class="dk-nempty">No identities match. Run Sign-in Forensics, Access Review or Conditional Access to populate identities.</div>${sug}`;
  return `<p class="inv-sub">${rows.length.toLocaleString()} ident${rows.length === 1 ? "ity" : "ities"}. Records are merged by email, UPN or samAccountName; a name-only match stays separate and is flagged below.</p>
  <div class="dk-itwrap"><table class="dk-itable"><thead><tr><th>Identity</th><th>Email addresses</th><th>Seen by</th></tr></thead><tbody>${rows.map((c) => `<tr><td>${openCell(c)}</td><td>${c.emails.length ? c.emails.map((e) => E(e)).join("<br>") : '<span class="dk-mut">—</span>'}</td><td>${srcChips(c.sources)}</td></tr>`).join("")}</tbody></table></div>${sug}`;
}

function coverageView(assets, ids, actionable, openCov) {
  const aCov = coverageMatrix(assets, ASSET_COV);
  const iCov = coverageMatrix(ids, IDENTITY_COV);
  const cell = (hit) => `<td class="inv-cell ${hit ? "yes" : "no"}">${hit ? "Yes" : "No"}</td>`;
  const matrix = (rows, cats, cov, nameHdr) => {
    if (!rows.length) return `<div class="dk-nempty">Nothing to show yet.</div>`;
    const gaps = cov.filter((r) => r.missing.length);
    return `<div class="dk-itwrap"><table class="dk-itable"><thead><tr><th>${nameHdr}</th>${cats.map((c) => `<th>${E(c.label)}</th>`).join("")}</tr></thead><tbody>${cov.map((r, i) => `<tr><td>${openCell(rows[i])}</td>${cats.map((c) => cell(r.cover[c.id])).join("")}</tr>`).join("")}</tbody></table></div>
    <p class="inv-sub">${gaps.length.toLocaleString()} of ${cov.length.toLocaleString()} have a coverage gap (a "No" above).</p>`;
  };
  // Actionable = gaps where the subject is already in scope for the control (a managed
  // host missing backup, a signed-in account not reconciled against HR), not every "No".
  const bar = `<div class="inv-covbar"><div class="inv-covtxt"><b>${(actionable || 0).toLocaleString()}</b> trackable coverage finding${actionable === 1 ? "" : "s"} — blind spots on subjects already in scope for the control. Publishing them adds owned, SLA-tracked findings to the queue and auto-closes any gap that is now covered.</div><button class="inv-covbtn" id="invCovCreate"${actionable || openCov ? "" : " disabled"}>${actionable || !openCov ? "Create coverage findings" : "Close fixed coverage findings"}</button></div>`;
  return `<p class="inv-sub">Which control sources have observed each host and identity. A "No" is a blind spot — an asset with no backup, an endpoint not in the fleet tool, a user not reconciled against HR.</p>
    ${bar}
    <h2 style="font-size:15px;margin:4px 0 8px">Host coverage</h2>${matrix(assets, ASSET_COV, aCov, "Host")}
    <h2 style="font-size:15px;margin:18px 0 8px">Identity coverage</h2>${matrix(ids, IDENTITY_COV, iCov, "Identity")}`;
}
