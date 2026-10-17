// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Payee Control — vendor master with bank-detail validation and bank-change control,
// the preventive control against vendor-bank-change (BEC) wire fraud. Every change to
// a payee's bank details opens a request that needs a second approver and a recorded
// out-of-band callback, then holds the new account for a cool-down before the first
// payment. See public/js/finsec/vendor-engine.js for the pure state machine.
//
//   renderVendors(main) -> void
//
// Local register: data is stored in THIS browser, scoped to your account. It records
// and enforces the control workflow; it is not a shared, server-identity-verified
// system (the "second approver" is enforced by a distinct name, not a login). Treat it
// as your payee control register — real validation, honest about where it runs.

import {
  validateBank, bankKey, bankLabel, createVendor, proposeChange, recordCallback,
  approveChange, rejectChange, refresh, canPay, screenFlags, markPaid, selfTest,
  HOLD_HOURS, WATCH_DAYS, toSinkFindings,
} from "/js/finsec/vendor-engine.js?v=20261017d";
import { attachSinkButton } from "../core/sink.js";
import { buildIndex, screenName } from "/js/finsec/sanctions-engine.js?v=20261017d";

// ── OFAC sanctions screening of payee names ──────────────────────────────
// A payee register that doesn't check names against the sanctions list is a
// control gap, so screen each payee against the same real OFAC SDN feed the
// Sanctions tool uses. The index is large (~19k), so it loads once per session
// and screening runs async; a hit shows as a flag (informational — it does not
// auto-block payment, which stays a human decision, same honesty as the tool).
let _sncIndex = null, _sncPromise = null;
const _sncCache = new Map();
const sancKey = (n) => String(n == null ? "" : n).trim().toLowerCase();
function loadSncIndex() {
  if (_sncIndex) return Promise.resolve(_sncIndex);
  if (_sncPromise) return _sncPromise;
  _sncPromise = fetch("/data/feeds/ofac-sdn.json", { cache: "default" })
    .then((r) => (r.ok ? r.json() : null))
    .then((feed) => { const e = feed && Array.isArray(feed.data) ? feed.data : null; _sncIndex = e && e.length ? buildIndex(e) : null; return _sncIndex; })
    .catch(() => null);
  return _sncPromise;
}

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.showToast || (() => {}))(m); } catch (_) {} };

const STATUS = {
  active:  { label: "Active",         c: "#2f9e56" },
  held:    { label: "Held (new acct)", c: "#b58100" },
  pending: { label: "Change pending", c: "#b00020" },
};
const FLAG_C = { block: "#b00020", high: "#d9480f", medium: "#b58100" };

function lsKey() { let uid = "anon"; try { uid = window.__dnUid || "anon"; } catch (_) {} return "dn_payees_" + uid; }
function load() { try { const r = JSON.parse(localStorage.getItem(lsKey()) || "[]"); return Array.isArray(r) ? r : []; } catch (_) { return []; } }
function save(list) { try { localStorage.setItem(lsKey(), JSON.stringify(list)); } catch (_) { toast("Could not save locally (storage blocked)."); } }

let injected = false;
function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "vn-css";
  st.textContent = `
  .vn{width:100%;font-size:14px;line-height:1.5}
  .vn .vn-hd{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap}
  .vn h1{font-size:1.7rem;margin:0;letter-spacing:-.01em}
  .vn .vn-tag{font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#fff;background:#2552c6;padding:3px 9px;border-radius:999px}
  .vn .vn-sub{color:var(--mut,#667085);margin:8px 0 14px;max-width:72ch}
  .vn .vn-warn{background:var(--acc-soft,rgba(181,129,0,.08));border:1px solid var(--line,#e6e8ee);border-left:3px solid #b58100;border-radius:8px;padding:11px 14px;color:var(--tx,#1a2230);font-size:.84rem;margin-bottom:16px}
  .vn .vn-card{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:12px;padding:16px 18px;margin-bottom:16px}
  .vn h3{font-size:.95rem;margin:0 0 10px}
  .vn label.vn-l{display:block;font-size:.76rem;font-weight:600;color:var(--mut,#667085);margin:0 0 4px}
  .vn input,.vn select,.vn textarea{width:100%;font:inherit;font-size:.86rem;padding:8px 10px;border:1px solid var(--line,#d7dbe3);border-radius:8px;background:var(--bg,#fbfcfe);color:var(--tx,#1a2230);box-sizing:border-box}
  .vn textarea{min-height:60px;resize:vertical}
  .vn .vn-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:12px}
  .vn .vn-row{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-top:12px}
  .vn .vn-btn{appearance:none;font:inherit;font-size:.84rem;font-weight:600;border:1px solid var(--line,#d7dbe3);background:var(--card,#fff);color:var(--tx,#1a2230);padding:8px 14px;border-radius:8px;cursor:pointer}
  .vn .vn-btn:hover{border-color:#9aa6bd}
  .vn .vn-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .vn .vn-btn.pri:hover{background:#1c42a6}
  .vn .vn-btn.danger{color:#b00020;border-color:#e6b8bd}
  .vn .vn-btn.sm{padding:5px 10px;font-size:.78rem}
  .vn .vn-err{color:#b00020;font-size:.8rem;margin-top:8px;white-space:pre-line}
  .vn .vn-list{border:1px solid var(--line,#e6e8ee);border-radius:12px;overflow:hidden}
  .vn table{width:100%;border-collapse:collapse;font-size:.86rem}
  .vn th{text-align:left;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#667085);font-weight:700;padding:9px 14px;background:var(--bg,#f7f8fb);border-bottom:1px solid var(--line,#e6e8ee)}
  .vn td{padding:10px 14px;border-bottom:1px solid var(--line,#eef0f4);vertical-align:top;overflow-wrap:anywhere}
  .vn tr:last-child td{border-bottom:0}
  .vn tr.vn-clk{cursor:pointer}
  .vn tr.vn-clk:hover td{background:var(--bg,#f7f8fb)}
  .vn .vn-pill{display:inline-block;font-size:.7rem;font-weight:700;color:#fff;padding:2px 8px;border-radius:999px;white-space:nowrap}
  .vn .vn-flags{display:flex;flex-wrap:wrap;gap:4px;margin-top:4px}
  .vn .vn-fl{font-size:.68rem;font-weight:600;padding:1px 6px;border-radius:5px;color:#fff}
  .vn .vn-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.82rem}
  .vn .vn-empty{padding:28px;text-align:center;color:var(--mut,#667085)}
  .vn .vn-kpis{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:14px}
  .vn .vn-kpi{background:var(--card,#fff);border:1px solid var(--line,#e6e8ee);border-radius:10px;padding:8px 16px;min-width:96px}
  .vn .vn-kpi b{display:block;font-size:1.35rem}
  .vn .vn-kpi span{font-size:.72rem;color:var(--mut,#667085);text-transform:uppercase;letter-spacing:.04em}
  .vn .vn-draw{position:fixed;inset:0;background:rgba(10,12,18,.45);display:flex;justify-content:flex-end;z-index:60}
  .vn .vn-drbox{width:min(560px,100%);background:var(--card,#fff);height:100%;overflow:auto;padding:22px;box-sizing:border-box}
  .vn .vn-drh{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:6px}
  .vn .vn-x{appearance:none;border:0;background:none;font-size:1.3rem;cursor:pointer;color:var(--mut,#667085);line-height:1}
  .vn .vn-sec{border-top:1px solid var(--line,#eef0f4);margin-top:16px;padding-top:14px}
  .vn .vn-log{font-size:.78rem;color:var(--tx,#1a2230)}
  .vn .vn-log div{padding:4px 0;border-bottom:1px dashed var(--line,#eef0f4)}
  .vn .vn-log .t{color:var(--mut,#667085);font-variant-numeric:tabular-nums}
  .vn .vn-note{font-size:.8rem;color:var(--mut,#667085);margin:0 0 8px}
  .vn .vn-ok{color:#2f9e56;font-weight:600}
  .vn .vn-selftest{font-size:.8rem}
  @media(max-width:620px){.vn th.vn-hide,.vn td.vn-hide{display:none}}
  `;
  document.head.appendChild(st);
}

export function renderVendors(main) {
  injectStyle();
  let list = load().map((v) => refresh(v));
  let drawerId = null;

  main.innerHTML = `
  <div class="vn">
    <div class="vn-hd"><h1>Payee Control</h1><span class="vn-tag">Financial Security</span></div>
    <div class="vn-sub">A vendor/payee register with real bank-detail validation and <b>bank-change control</b> — the
      preventive control against vendor-bank-change (business email compromise) wire fraud. A change to a payee's
      bank details needs a second approver and a recorded call-back, then the new account is held before its first
      payment.</div>
    <div class="vn-warn"><b>Local control register.</b> This data lives in this browser, scoped to your account. It
      records and enforces the change-control workflow and validates bank details, but the second approver is checked
      by a distinct name, not a verified login. Use it as your payee control register; your process and your banking
      portal remain the system of record.</div>

    <div class="vn-card" id="vnAddCard">
      <h3>Add a payee</h3>
      <div class="vn-grid">
        <div><label class="vn-l">Payee name</label><input id="vnName" placeholder="Legal name on the invoice" autocomplete="off"></div>
        <div><label class="vn-l">Bank detail type</label><select id="vnKind"><option value="iban">IBAN (SEPA / international)</option><option value="aba">US account + ABA routing</option></select></div>
        <div><label class="vn-l">Added by (your name)</label><input id="vnBy" placeholder="Your name" autocomplete="off"></div>
      </div>
      <div class="vn-grid" id="vnBankFields" style="margin-top:12px"></div>
      <div class="vn-row"><button class="vn-btn pri" id="vnAdd">Add payee</button><button class="vn-btn" id="vnTest">Self-test</button><span class="vn-selftest" id="vnTestOut"></span></div>
      <div class="vn-err" id="vnAddErr"></div>
    </div>

    <div id="vnKpis"></div>
    <div id="vnBody"></div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);

  function bankFieldsHtml(kind) {
    if (kind === "aba") return `
      <div><label class="vn-l">Account number</label><input id="vnAcct" class="vn-mono" placeholder="123456789" autocomplete="off"></div>
      <div><label class="vn-l">ABA routing (9 digits)</label><input id="vnRout" class="vn-mono" placeholder="021000021" autocomplete="off"></div>`;
    return `
      <div><label class="vn-l">IBAN</label><input id="vnIban" class="vn-mono" placeholder="Country code, check digits, account" autocomplete="off"></div>
      <div><label class="vn-l">SWIFT / BIC (optional)</label><input id="vnBic" class="vn-mono" placeholder="8 or 11 characters" autocomplete="off"></div>`;
  }
  function readBank() {
    const kind = $("vnKind").value;
    if (kind === "aba") return { kind, account: $("vnAcct").value.trim(), routing: $("vnRout").value.trim() };
    return { kind, iban: $("vnIban").value.trim(), swift: $("vnBic").value.trim() || undefined };
  }
  $("vnBankFields").innerHTML = bankFieldsHtml("iban");
  $("vnKind").addEventListener("change", () => { $("vnBankFields").innerHTML = bankFieldsHtml($("vnKind").value); });

  $("vnTest").addEventListener("click", () => {
    const { pass, results } = selfTest();
    $("vnTestOut").innerHTML = pass ? `<span class="vn-ok">Self-test passed</span> — ${results.length}/${results.length} checks`
      : `<span style="color:#b00020;font-weight:600">Self-test failed</span> — ${results.filter((r) => !r.pass).map((r) => r.name).join(", ")}`;
  });

  $("vnAdd").addEventListener("click", () => {
    const name = $("vnName").value.trim(), by = $("vnBy").value.trim();
    const err = $("vnAddErr"); err.textContent = "";
    if (!name) return err.textContent = "Enter a payee name.";
    if (!by) return err.textContent = "Enter your name (the person adding this payee).";
    const bank = readBank();
    const r = validateBank(bank);
    if (!r.ok) return err.textContent = r.errors.join("\n");
    if (list.some((v) => v.name.toLowerCase() === name.toLowerCase())) return err.textContent = "A payee with this name already exists.";
    const v = createVendor({ id: "py_" + Date.now().toString(36) + Math.random().toString(36).slice(2, 6), name, bank, by });
    list.push(v); save(list);
    $("vnName").value = ""; $("vnBankFields").innerHTML = bankFieldsHtml($("vnKind").value);
    toast("Payee added — pending verification and approval.");
    render();
    openDrawer(v.id);
  });

  function render() {
    list = list.map((v) => refresh(v)); save(list);
    const act = list.filter((v) => v.status === "active").length;
    const held = list.filter((v) => v.status === "held").length;
    const pend = list.filter((v) => v.status === "pending").length;
    $("vnKpis").innerHTML = list.length ? `<div class="vn-kpis">
      <div class="vn-kpi"><b>${list.length}</b><span>Payees</span></div>
      <div class="vn-kpi"><b style="color:#2f9e56">${act}</b><span>Active</span></div>
      <div class="vn-kpi"><b style="color:#b58100">${held}</b><span>On hold</span></div>
      <div class="vn-kpi"><b style="color:${pend ? "#b00020" : "inherit"}">${pend}</b><span>Change pending</span></div>
    </div>` : "";
    if (list.length) {
      const row = document.createElement("div"); row.className = "vn-row"; $("vnKpis").appendChild(row);
      // Real register entries only (no example data exists here); OFAC flags come from the live screen cache.
      attachSinkButton(row, () => ({ findings: toSinkFindings(list, { sanctions: (v) => _sncCache.get(sancKey(v.name)) || null }), sample: false }), "payees", { dataset: "payee register" });
    }
    const body = $("vnBody");
    if (!list.length) { body.innerHTML = `<div class="vn-card vn-empty">No payees yet. Add one above to start a control register.</div>`; return; }
    body.innerHTML = `<div class="vn-list"><table>
      <thead><tr><th>Payee</th><th>Status</th><th class="vn-hide">Bank account</th><th>Can pay?</th><th>Flags</th></tr></thead>
      <tbody>${list.map(rowHtml).join("")}</tbody></table></div>`;
    body.querySelectorAll("tr[data-id]").forEach((tr) => tr.addEventListener("click", () => openDrawer(tr.dataset.id)));
    ensureSanctions();
  }

  // Screen any not-yet-screened payees against the OFAC SDN index, then re-render
  // once so the hits appear. Re-entry is safe: once every name is cached, nothing
  // new is added and the re-render is skipped (no loop).
  async function ensureSanctions() {
    try {
      const idx = await loadSncIndex(); if (!idx) return;
      let added = false;
      for (const v of list) {
        const k = sancKey(v.name); if (_sncCache.has(k)) continue;
        const m = screenName(v.name, idx, { minScore: 70, limit: 1 })[0] || null;
        let flag = null;
        if (m) {
          const level = m.band === "exact" ? "block" : m.band === "strong" ? "high" : "medium";
          const word = m.band === "exact" ? "exact" : m.band === "strong" ? "strong" : "possible";
          flag = { code: "ofac", level, text: "OFAC " + word + " match: " + (m.matchedName || m.name) + (m.program ? " (" + m.program + ")" : "") };
        }
        _sncCache.set(k, flag); added = true;
      }
      if (added) render();
    } catch (_) {}
  }
  const withSanc = (v, flags) => { const f = _sncCache.get(sancKey(v.name)); return f ? flags.concat([f]) : flags; };

  function rowHtml(v) {
    const s = STATUS[v.status] || STATUS.pending;
    const pay = canPay(v);
    const flags = withSanc(v, screenFlags(v));
    return `<tr class="vn-clk" data-id="${esc(v.id)}">
      <td><b>${esc(v.name)}</b></td>
      <td><span class="vn-pill" style="background:${s.c}">${s.label}</span></td>
      <td class="vn-hide vn-mono">${v.bank ? esc(bankLabel(v.bank)) : v.change ? "proposed: " + esc(bankLabel(v.change.bank)) : "—"}</td>
      <td style="color:${pay.ok ? "#2f9e56" : "#b00020"};font-weight:600">${pay.ok ? "Yes" : "No"}</td>
      <td>${flags.length ? `<div class="vn-flags">${flags.map((f) => `<span class="vn-fl" style="background:${FLAG_C[f.level] || "#667085"}">${esc(f.text)}</span>`).join("")}</div>` : `<span class="vn-note">—</span>`}</td>
    </tr>`;
  }

  function fmtTs(ts) { return ts ? new Date(ts).toLocaleString() : "—"; }

  function openDrawer(id) {
    drawerId = id; closeDrawer();
    const v = list.find((x) => x.id === id); if (!v) return;
    refresh(v);
    const s = STATUS[v.status] || STATUS.pending;
    const pay = canPay(v);
    const flags = withSanc(v, screenFlags(v));
    const wrap = document.createElement("div"); wrap.className = "vn-draw"; wrap.id = "vnDraw";
    const pendingChange = v.change;
    wrap.innerHTML = `<div class="vn-drbox">
      <div class="vn-drh"><h3 style="font-size:1.2rem;margin:0">${esc(v.name)}</h3><button class="vn-x" id="vnClose" aria-label="Close">×</button></div>
      <div><span class="vn-pill" style="background:${s.c}">${s.label}</span>
        <span style="margin-left:8px;color:${pay.ok ? "#2f9e56" : "#b00020"};font-weight:600">${pay.ok ? "Payment allowed" : "Payment blocked"}</span></div>
      <p class="vn-note" style="margin-top:6px">${pay.ok ? "This payee's bank details are verified and past the new-account hold." : esc(pay.reason)}</p>

      <div class="vn-sec">
        <h3>Current bank account</h3>
        <p class="vn-mono">${v.bank ? esc(bankLabel(v.bank)) : "<span class='vn-note'>Not yet verified — see the pending change below.</span>"}</p>
        ${v.holdUntil && v.status === "held" ? `<p class="vn-note">New account held until ${fmtTs(v.holdUntil)}.</p>` : ""}
        ${flags.length ? `<div class="vn-flags">${flags.map((f) => `<span class="vn-fl" style="background:${FLAG_C[f.level] || "#667085"}">${esc(f.text)}</span>`).join("")}</div>` : ""}
        ${pay.ok ? `<div class="vn-row"><button class="vn-btn sm" id="vnPay">Record a payment released</button></div>` : ""}
      </div>

      ${pendingChange ? `
      <div class="vn-sec">
        <h3>Pending ${v.history.length || v.firstPaymentAt ? "bank change" : "verification"}</h3>
        <p class="vn-note">Proposed account: <b class="vn-mono">${esc(bankLabel(pendingChange.bank))}</b> · proposed by <b>${esc(pendingChange.by || "—")}</b></p>
        <div class="vn-sec" style="border:0;margin:0;padding:0">
          <h3 style="font-size:.85rem">1. Record out-of-band callback</h3>
          ${pendingChange.callback
            ? `<p class="vn-note vn-ok">Verified by ${esc(pendingChange.callback.by || "—")}${pendingChange.callback.phone ? " · called " + esc(pendingChange.callback.phone) : ""} — ${esc(pendingChange.callback.note || "")}</p>`
            : `<div class="vn-grid">
                 <div><label class="vn-l">Verified by</label><input id="vnCbBy" placeholder="your name"></div>
                 <div><label class="vn-l">Number called (known-good)</label><input id="vnCbPhone" placeholder="+1 555 0100"></div>
               </div>
               <div style="margin-top:8px"><label class="vn-l">What was confirmed</label><textarea id="vnCbNote" placeholder="Who you called, on which number, and what they confirmed"></textarea></div>
               <div class="vn-row"><button class="vn-btn sm" id="vnCbSave">Record callback</button></div>`}
        </div>
        <div class="vn-sec" style="border:0;margin-top:10px;padding:0">
          <h3 style="font-size:.85rem">2. Second-approver sign-off</h3>
          <p class="vn-note">Must be a different person from <b>${esc(pendingChange.by || "the proposer")}</b>, and the callback must be recorded first.</p>
          <div class="vn-grid"><div><label class="vn-l">Approver name</label><input id="vnApBy" placeholder="Not the proposer"></div></div>
          <div class="vn-row">
            <button class="vn-btn pri sm" id="vnApprove">Approve change</button>
            <button class="vn-btn danger sm" id="vnReject">Reject</button>
          </div>
          <div class="vn-err" id="vnDrErr"></div>
        </div>
      </div>` : `
      <div class="vn-sec">
        <h3>Change bank details</h3>
        <p class="vn-note">Opens a controlled change: a second approver and a recorded callback are required, then a ${HOLD_HOURS}h hold.</p>
        <div class="vn-grid">
          <div><label class="vn-l">Type</label><select id="vnChKind"><option value="iban">IBAN</option><option value="aba">US account + ABA</option></select></div>
          <div><label class="vn-l">Proposed by</label><input id="vnChBy" placeholder="your name"></div>
        </div>
        <div class="vn-grid" id="vnChFields" style="margin-top:10px"></div>
        <div class="vn-row"><button class="vn-btn sm" id="vnChPropose">Propose change</button></div>
        <div class="vn-err" id="vnDrErr"></div>
      </div>`}

      ${v.history.length ? `<div class="vn-sec"><h3>Retired accounts</h3>${v.history.map((h) => `<p class="vn-note vn-mono">${esc(h.label)} · retired ${fmtTs(h.retiredAt)}</p>`).join("")}</div>` : ""}

      <div class="vn-sec"><h3>Audit trail</h3><div class="vn-log">${v.audit.slice().reverse().map((a) => `<div><span class="t">${fmtTs(a.at)}</span> — ${esc(a.action)}${a.by ? " by " + esc(a.by) : ""}${a.account ? " (" + esc(a.account) + ")" : ""}${a.to ? " → " + esc(a.to) : ""}${a.reason ? " — " + esc(a.reason) : ""}</div>`).join("")}</div></div>

      <div class="vn-row vn-sec"><button class="vn-btn danger sm" id="vnDel">Delete payee</button></div>
    </div>`;
    main.querySelector(".vn").appendChild(wrap);
    wrap.addEventListener("click", (e) => { if (e.target === wrap) closeDrawer(); });
    const q = (id) => wrap.querySelector("#" + id);
    q("vnClose").addEventListener("click", closeDrawer);

    if (q("vnPay")) q("vnPay").addEventListener("click", () => { markPaid(v); save(list); toast("Payment recorded."); render(); openDrawer(id); });
    if (q("vnDel")) q("vnDel").addEventListener("click", async () => {
      const yes = await window.dnConfirm("Delete payee", "Delete “" + v.name + "” and its control history? This cannot be undone.", { danger: true, submitText: "Delete" });
      if (!yes) return;
      list = list.filter((x) => x.id !== id); save(list); closeDrawer(); render();
    });

    if (q("vnCbSave")) q("vnCbSave").addEventListener("click", () => {
      const r = recordCallback(v, { by: q("vnCbBy").value.trim(), phone: q("vnCbPhone").value.trim(), note: q("vnCbNote").value.trim() });
      if (!r.ok) return q("vnDrErr").textContent = r.errors.join("\n");
      save(list); openDrawer(id);
    });
    if (q("vnApprove")) q("vnApprove").addEventListener("click", () => {
      const r = approveChange(v, { by: q("vnApBy").value.trim() });
      if (!r.ok) return q("vnDrErr").textContent = r.errors.join("\n");
      save(list); toast("Change approved — account held " + HOLD_HOURS + "h before first payment."); render(); openDrawer(id);
    });
    if (q("vnReject")) q("vnReject").addEventListener("click", () => {
      const r = rejectChange(v, { by: q("vnApBy") ? q("vnApBy").value.trim() : "", reason: "rejected in review" });
      if (!r.ok) return q("vnDrErr").textContent = r.errors.join("\n");
      save(list); toast("Change rejected."); render(); openDrawer(id);
    });

    if (q("vnChFields")) {
      const chFields = (k) => k === "aba"
        ? `<div><label class="vn-l">Account number</label><input id="vnChAcct" class="vn-mono" placeholder="123456789"></div><div><label class="vn-l">ABA routing</label><input id="vnChRout" class="vn-mono" placeholder="021000021"></div>`
        : `<div><label class="vn-l">IBAN</label><input id="vnChIban" class="vn-mono" placeholder="Country code, check digits, account"></div><div><label class="vn-l">SWIFT / BIC (optional)</label><input id="vnChBic" class="vn-mono" placeholder="8 or 11 characters"></div>`;
      q("vnChFields").innerHTML = chFields("iban");
      q("vnChKind").addEventListener("change", () => { q("vnChFields").innerHTML = chFields(q("vnChKind").value); });
      q("vnChPropose").addEventListener("click", () => {
        const k = q("vnChKind").value;
        const bank = k === "aba" ? { kind: k, account: q("vnChAcct").value.trim(), routing: q("vnChRout").value.trim() }
          : { kind: k, iban: q("vnChIban").value.trim(), swift: (q("vnChBic").value.trim() || undefined) };
        const by = q("vnChBy").value.trim();
        if (!by) return q("vnDrErr").textContent = "Enter who is proposing the change.";
        const r = proposeChange(v, { bank, by });
        if (!r.ok) return q("vnDrErr").textContent = r.errors.join("\n");
        save(list); toast("Change proposed — record the callback and get a second approver."); render(); openDrawer(id);
      });
    }
  }

  function closeDrawer() { const d = main.querySelector("#vnDraw"); if (d) d.remove(); }

  render();
}
