// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// VAULT — Treasury & Fund Safeguarding (UI).
//
// A control plane for money a company holds at its own regulated, insured bank(s).
// VAULT does NOT hold or move funds and collects no deposits — it is the tamper-evident
// record-of-truth and the approval/segregation-of-duties control layer. Real settlement
// happens at your bank; VAULT keeps the ledger honest and reconciles against it.
//
// The money math lives in vault/ledger.js (BigInt cents, enforced double-entry,
// SHA-256 hash chain, no-overdraft guard, idempotency) — exhaustively tested.
//
//   renderVault(main) -> void

import { Ledger, toCents, fmtCents, screenTransfer } from "/js/vault/ledger.js?v=20261011a";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.dnToast || window.showToast || (() => {}))(m); } catch (_) {} };
const STORE = "dn_vault_v1";

function loadLedger() {
  try { const raw = localStorage.getItem(STORE); if (raw) return Ledger.load(JSON.parse(raw)); } catch (_) {}
  return null;
}
function saveLedger(L) { try { localStorage.setItem(STORE, JSON.stringify(L.snapshot())); } catch (e) { toast("Could not save locally: " + e.message); } }

function injectStyle() {
  if (document.getElementById("vlt-style")) return;
  const s = document.createElement("style"); s.id = "vlt-style";
  s.textContent = `
  .vlt{max-width:1180px;margin:0 auto;padding:4px 2px 48px;min-width:0;width:100%;box-sizing:border-box}
  .vlt .vhd{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;margin:8px 0 4px}
  .vlt .vhd h1{font-size:1.5rem;margin:0;font-weight:800;letter-spacing:-.01em}
  .vlt .vtag{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#8a5a00;background:rgba(245,158,11,.16);padding:3px 9px;border-radius:999px}
  .vlt .vsub{color:var(--mut,#667085);font-size:.9rem;max-width:760px;line-height:1.5;margin:2px 0}
  .vlt .vbanner{border:1px solid #f0c36d;background:rgba(240,195,109,.1);color:#7a5b00;border-radius:10px;padding:10px 13px;font-size:.82rem;line-height:1.5;margin:10px 0}
  .vlt .vbad{border:1px solid #e0697a;background:rgba(224,105,122,.12);color:#8a1a2b;border-radius:10px;padding:11px 14px;font-weight:700;margin:10px 0}
  .vlt .vok{color:#1a7f37;font-weight:700}
  .vlt .vtabs{display:flex;flex-wrap:wrap;gap:6px;border-bottom:1px solid var(--bd,#e3e8ef);margin:12px 0 16px}
  .vlt .vtab{appearance:none;font:inherit;font-size:.85rem;font-weight:600;border:0;background:none;color:var(--mut,#667085);padding:8px 12px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
  .vlt .vtab.on{color:#2552c6;border-bottom-color:#2552c6}
  .vlt .vkpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,170px),1fr));gap:11px;margin:0 0 16px}
  .vlt .vkpi{border:1px solid var(--bd,#e3e8ef);border-radius:12px;padding:12px 14px;background:var(--card,#fff);min-width:0}
  .vlt .vkpi .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#8893a7);font-weight:600}
  .vlt .vkpi .v{font-size:1.25rem;font-weight:800;margin-top:3px;overflow-wrap:anywhere}
  .vlt table{width:100%;border-collapse:collapse;font-size:.86rem}
  .vlt th,.vlt td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd,#eef1f6);vertical-align:top}
  .vlt th{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut,#8893a7)}
  .vlt td.num,.vlt th.num{text-align:right;font-variant-numeric:tabular-nums;font-family:ui-monospace,monospace}
  .vlt .vcard{border:1px solid var(--bd,#e3e8ef);border-radius:14px;background:var(--card,#fff);padding:15px 16px;margin-bottom:14px;overflow-x:auto}
  .vlt table{min-width:min-content}
  .vlt .vcard h3{margin:0 0 10px;font-size:1rem;font-weight:700}
  .vlt .vgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,180px),1fr));gap:10px}
  .vlt .vgrid>*{min-width:0}
  .vlt label.f{display:flex;flex-direction:column;gap:4px;font-size:.78rem;color:var(--mut,#667085)}
  .vlt input,.vlt select{font:inherit;font-size:.86rem;border:1px solid var(--bd,#d7deea);border-radius:8px;padding:8px 10px;background:var(--bg2,#fafbfc);color:inherit;width:100%;box-sizing:border-box}
  .vlt textarea{font-family:ui-monospace,monospace;font-size:12px;width:100%;box-sizing:border-box;min-height:100px;border:1px solid var(--bd,#d7deea);border-radius:8px;padding:9px 10px;background:var(--bg2,#fafbfc);color:inherit}
  .vlt .btn2{appearance:none;font:inherit;font-size:.82rem;font-weight:600;border:1px solid var(--bd,#d7deea);background:var(--card,#fff);color:inherit;border-radius:8px;padding:8px 13px;cursor:pointer}
  .vlt .btn2:hover{background:rgba(47,95,255,.06);border-color:#9db4ff}
  .vlt .btn2.pri{background:#2552c6;border-color:#2552c6;color:#fff}.vlt .btn2.pri:hover{background:#1c45ad}
  .vlt .btn2.danger{color:#b00020;border-color:#e0a7b0}.vlt .btn2.danger:hover{background:rgba(176,0,32,.06)}
  .vlt .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px}
  .vlt .pill{font-size:.72rem;font-weight:700;border-radius:999px;padding:2px 9px;color:#fff;display:inline-block}
  .vlt .mono{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--mut,#8893a7);word-break:break-all}
  .vlt .flags{font-size:.76rem;color:#8a5a00;margin-top:4px}
  .vlt .empty{text-align:center;color:var(--mut,#8893a7);padding:28px 10px;font-size:.88rem}
  `;
  document.head.appendChild(s);
}

const STATUS_COLOR = { pending: "#b58100", approved: "#2b6cb0", released: "#6b46c1", settled: "#1a7f37", rejected: "#b00020" };

export function renderVault(main) {
  injectStyle();
  let L = loadLedger();
  let tab = "overview";

  const shell = () => {
    main.innerHTML = `
    <div class="vlt">
      <div class="vhd"><h1>VAULT</h1><span class="vtag">Treasury &amp; Safeguarding</span></div>
      <div class="vsub">The control &amp; record layer for funds your company holds at its own regulated, insured bank.
        Every movement is double-entry, enforced in exact cents, dual-approved, and written to a tamper-evident hash chain.</div>
      <div class="vbanner"><b>VAULT is not a bank and does not hold your money.</b> It safeguards the <i>record and the controls</i> for
        money that lives in your real bank account(s); settlement happens there, and VAULT reconciles against it. It never collects deposits.
        For production use the ledger must be stored server-side — this build persists locally in your browser so you can evaluate it.</div>
      <div class="vtabs" id="vtabs">
        ${["overview:Overview", "move:Move funds", "approvals:Approvals", "audit:Audit log", "reconcile:Reconcile", "setup:Setup"].map((t) => {
          const [id, label] = t.split(":"); return `<button class="vtab${id === tab ? " on" : ""}" data-tab="${id}">${esc(label)}</button>`; }).join("")}
      </div>
      <div id="vbody"></div>
    </div>`;
    main.querySelectorAll(".vtab").forEach((b) => b.onclick = () => { tab = b.dataset.tab; shell(); });
    body();
  };

  const body = () => {
    const host = main.querySelector("#vbody");
    if (!L && tab !== "setup") { host.innerHTML = `<div class="vcard"><div class="empty">No treasury initialized yet. Go to <b>Setup</b> to create accounts and opening balances.</div></div>`; return; }
    if (tab === "overview") renderOverview(host);
    else if (tab === "move") renderMove(host);
    else if (tab === "approvals") renderApprovals(host);
    else if (tab === "audit") renderAudit(host);
    else if (tab === "reconcile") renderReconcile(host);
    else renderSetup(host);
  };

  // --- Overview ---
  function renderOverview(host) {
    const tb = L.trialBalance();
    const chain = L.verifyChain();
    const accts = [...L.accounts.values()];
    const total = accts.filter((a) => a.normal === "debit").reduce((s, a) => s + L.balance(a.id).balance, 0n);
    const pending = [...L.transfers.values()].filter((t) => t.status === "pending" || t.status === "approved");
    let html = "";
    if (!chain.ok) html += `<div class="vbad">INTEGRITY ALERT: the audit chain failed verification at entry #${chain.brokenAt}. The ledger may have been altered outside VAULT. Do not trust these balances until investigated.</div>`;
    html += `<div class="vkpis">
      ${kpi("Assets on ledger", fmtCents(total))}
      ${kpi("Accounts", String(accts.length))}
      ${kpi("Journal entries", String(L.journal.length))}
      ${kpi("Pending movements", String(pending.length))}
      ${kpi("Trial balance", tb.balanced ? `<span class="vok">Balanced</span>` : `<span style="color:#b00020">OFF by ${esc(fmtCents(tb.debits - tb.credits))}</span>`)}
      ${kpi("Audit chain", chain.ok ? `<span class="vok">Verified</span>` : `<span style="color:#b00020">BROKEN</span>`)}
    </div>`;
    html += `<div class="vcard"><h3>Account balances</h3>${accts.length ? `<table><thead><tr><th>Account</th><th>Type</th><th class="num">Debits</th><th class="num">Credits</th><th class="num">Balance</th></tr></thead><tbody>${accts.map((a) => { const b = L.balance(a.id); return `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td class="num">${esc(fmtCents(b.debits))}</td><td class="num">${esc(fmtCents(b.credits))}</td><td class="num"><b>${esc(fmtCents(b.balance))}</b></td></tr>`; }).join("")}</tbody></table>` : `<div class="empty">No accounts.</div>`}</div>`;
    host.innerHTML = html;
  }
  const kpi = (k, v) => `<div class="vkpi"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`;

  // --- Move funds (create a transfer instruction) ---
  function renderMove(host) {
    const accts = [...L.accounts.values()];
    const opt = (a) => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.type)})</option>`;
    host.innerHTML = `<div class="vcard"><h3>New fund movement</h3>
      <div class="vgrid">
        <label class="f">From account<select id="mFrom">${accts.map(opt).join("")}</select></label>
        <label class="f">To account<select id="mTo">${accts.map(opt).join("")}</select></label>
        <label class="f">Amount (USD)<input id="mAmt" placeholder="0.00" inputmode="decimal"></label>
        <label class="f">Payee (optional)<input id="mPayee" placeholder="vendor / beneficiary"></label>
        <label class="f">Initiated by<input id="mBy" placeholder="your user id"></label>
        <label class="f">Memo<input id="mMemo" placeholder="what is this for"></label>
      </div>
      <div class="row"><button class="btn2 pri" id="mCreate">Create movement (requires approval)</button></div>
      <div class="flags" id="mScreen"></div>
      <div class="vsub" style="margin-top:8px">A movement posts nothing until ${L.policy.minApprovers} distinct people (never the initiator) approve it and it is released. VAULT refuses to release more than the source account holds.</div>
    </div>`;
    const $ = (id) => host.querySelector("#" + id);
    // live screen preview
    const preview = () => {
      try { const amt = toCents($("mAmt").value || "0"); const s = screenTransfer(L, { from: $("mFrom").value, amount: amt, payee: $("mPayee").value, by: $("mBy").value }); $("mScreen").innerHTML = s.flags.length ? "Pre-flight screen (" + s.level + "): " + s.flags.map(esc).join(" · ") : ""; } catch (_) { $("mScreen").innerHTML = ""; }
    };
    ["mAmt", "mPayee", "mFrom"].forEach((id) => $(id).addEventListener("input", preview));
    $("mCreate").onclick = () => {
      try {
        const id = "t" + Date.now().toString(36);
        L.createTransfer({ id, from: $("mFrom").value, to: $("mTo").value, amount: $("mAmt").value, payee: $("mPayee").value.trim(), by: $("mBy").value.trim(), memo: $("mMemo").value.trim(), ts: Date.now() });
        saveLedger(L); toast("Movement created — awaiting approval"); tab = "approvals"; shell();
      } catch (e) { toast(e.message); }
    };
  }

  // --- Approvals queue ---
  function renderApprovals(host) {
    const open = [...L.transfers.values()].filter((t) => t.status === "pending" || t.status === "approved");
    if (!open.length) { host.innerHTML = `<div class="vcard"><div class="empty">No movements awaiting approval or release.</div></div>`; return; }
    host.innerHTML = open.map((t) => {
      const c = STATUS_COLOR[t.status];
      return `<div class="vcard" data-t="${esc(t.id)}">
        <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">
          <span class="pill" style="background:${c}">${esc(t.status)}</span>
          <b>${esc(fmtCents(t.amount))}</b>
          <span class="vsub" style="margin:0">${esc(L.accounts.get(t.from).name)} &rarr; ${esc(L.accounts.get(t.to).name)}${t.payee ? " · " + esc(t.payee) : ""}</span>
          <span class="vsub" style="margin:0 0 0 auto">by ${esc(t.by)} · approvals ${t.approvers.length}/${t.required}</span>
        </div>
        ${t.memo ? `<div class="vsub" style="margin:4px 0">${esc(t.memo)}</div>` : ""}
        ${t.screen && t.screen.flags.length ? `<div class="flags">Screen (${esc(t.screen.level)}): ${t.screen.flags.map(esc).join(" · ")}</div>` : ""}
        ${t.approvers.length ? `<div class="vsub" style="margin:4px 0">Approved by: ${t.approvers.map(esc).join(", ")}</div>` : ""}
        <div class="row">
          <input placeholder="approver / releaser id" class="apId" style="max-width:220px">
          ${t.status === "pending" ? `<button class="btn2 aApprove">Approve</button>` : ""}
          ${t.status === "approved" ? `<button class="btn2 pri aRelease">Release (post)</button>` : ""}
          <button class="btn2 danger aReject">Reject</button>
        </div>
      </div>`;
    }).join("");
    host.querySelectorAll("[data-t]").forEach((card) => {
      const id = card.dataset.t;
      const who = () => (card.querySelector(".apId").value || "").trim();
      const ap = card.querySelector(".aApprove"); if (ap) ap.onclick = () => { try { if (!who()) return toast("Enter the approver id"); L.approve(id, who()); saveLedger(L); shell(); } catch (e) { toast(e.message); } };
      const rl = card.querySelector(".aRelease"); if (rl) rl.onclick = () => { try { if (!who()) return toast("Enter the releaser id"); L.release(id, who(), Date.now()); saveLedger(L); toast("Released and posted to the ledger"); shell(); } catch (e) { toast(e.message); } };
      const rj = card.querySelector(".aReject"); if (rj) rj.onclick = () => { try { L.reject(id, who(), ""); saveLedger(L); shell(); } catch (e) { toast(e.message); } };
    });
  }

  // --- Audit log ---
  function renderAudit(host) {
    const chain = L.verifyChain();
    let html = `<div class="vcard"><h3>Tamper-evident audit chain</h3>
      <div class="row"><button class="btn2" id="aVerify">Verify chain now</button>
      <span id="aVerOut">${chain.ok ? `<span class="vok">Verified — ${L.journal.length} entries, intact.</span>` : `<span style="color:#b00020">BROKEN at entry #${chain.brokenAt}.</span>`}</span></div></div>`;
    html += `<div class="vcard"><h3>Journal (append-only)</h3>${L.journal.length ? `<table><thead><tr><th>#</th><th>Memo</th><th>Postings</th><th class="num">Amount</th><th>Hash</th></tr></thead><tbody>${L.journal.map((e) => `<tr><td>${e.seq}</td><td>${esc(e.memo)}</td><td class="mono">${e.postings.map((p) => `${esc(p.side === "debit" ? "DR" : "CR")} ${esc(L.accounts.get(p.account) ? L.accounts.get(p.account).name : p.account)}`).join("<br>")}</td><td class="num">${esc(fmtCents(e.postings.filter((p) => p.side === "debit").reduce((s, p) => s + p.amount, 0n)))}</td><td class="mono">${esc(e.hash.slice(0, 12))}…</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No entries yet.</div>`}</div>`;
    host.innerHTML = html;
    host.querySelector("#aVerify").onclick = () => { const v = L.verifyChain(); host.querySelector("#aVerOut").innerHTML = v.ok ? `<span class="vok">Verified — ${L.journal.length} entries, intact.</span>` : `<span style="color:#b00020">BROKEN at entry #${v.brokenAt}.</span>`; };
  }

  // --- Reconcile ---
  function renderReconcile(host) {
    host.innerHTML = `<div class="vcard"><h3>Reconcile against your bank statement</h3>
      <div class="vsub" style="margin:0 0 8px">Paste bank lines as <code>amount,reference</code> (one per line). VAULT matches released movements to real bank debits and flags anything unmatched on either side — the gap where fraud and errors hide.</div>
      <textarea id="rLines" placeholder="2500.00,ACME WIRE REF t1&#10;264000.00,INITECH PMT"></textarea>
      <div class="row"><button class="btn2 pri" id="rRun">Reconcile</button></div>
      <div id="rOut" style="margin-top:12px"></div>
    </div>`;
    host.querySelector("#rRun").onclick = () => {
      const lines = host.querySelector("#rLines").value.trim().split(/\n+/).filter(Boolean).map((l) => { const [amt, ...ref] = l.split(","); return { amount: amt.trim(), ref: ref.join(",").trim() }; });
      let res; try { res = L.reconcile(lines); } catch (e) { return toast(e.message); }
      saveLedger(L);
      host.querySelector("#rOut").innerHTML = `
        <div class="vkpis"><div class="vkpi"><div class="k">Matched</div><div class="v vok">${res.matched.length}</div></div>
        <div class="vkpi"><div class="k">Unmatched (bank)</div><div class="v" style="${res.unmatchedBank.length ? "color:#b00020" : ""}">${res.unmatchedBank.length}</div></div>
        <div class="vkpi"><div class="k">Unmatched (ledger)</div><div class="v" style="${res.unmatchedLedger.length ? "color:#b00020" : ""}">${res.unmatchedLedger.length}</div></div></div>
        ${res.unmatchedBank.length ? `<div class="vcard"><h3>On the bank, not matched in VAULT</h3><table><tbody>${res.unmatchedBank.map((b) => `<tr><td class="num">${esc(b.amount)}</td><td class="mono">${esc(b.ref)}</td></tr>`).join("")}</tbody></table></div>` : ""}
        ${res.unmatchedLedger.length ? `<div class="vcard"><h3>Released in VAULT, not seen at the bank</h3><table><tbody>${res.unmatchedLedger.map((t) => `<tr><td>${esc(t.id)}</td><td class="num">${esc(t.amount)}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
    };
  }

  // --- Setup ---
  function renderSetup(host) {
    const have = !!L;
    host.innerHTML = `
    ${!have ? `<div class="vcard"><h3>Quick start</h3><div class="vsub" style="margin:0 0 8px">Create a standard treasury: an Operating (bank) asset, an Opening equity account, and an Outgoing clearing account, with an opening balance.</div>
      <div class="vgrid"><label class="f">Opening balance (USD)<input id="qOpen" placeholder="100000.00" inputmode="decimal"></label></div>
      <div class="row"><button class="btn2 pri" id="qInit">Initialize treasury</button></div></div>` : ""}
    <div class="vcard"><h3>Add account</h3>
      <div class="vgrid">
        <label class="f">Name<input id="aName" placeholder="e.g. Payroll (bank)"></label>
        <label class="f">Type<select id="aType"><option value="asset">asset (bank / cash)</option><option value="clearing">clearing</option><option value="liability">liability</option><option value="customer">customer balance</option><option value="equity">equity</option><option value="income">income</option><option value="expense">expense</option></select></label>
      </div>
      <div class="row"><button class="btn2" id="aAdd" ${have ? "" : "disabled"}>Add account</button></div>
    </div>
    <div class="vcard"><h3>Policy</h3>
      <div class="vgrid">
        <label class="f">Minimum approvers<input id="pMin" type="number" min="1" value="${have ? L.policy.minApprovers : 2}"></label>
      </div>
      <div class="row"><button class="btn2" id="pSave" ${have ? "" : "disabled"}>Save policy</button></div>
    </div>
    <div class="vcard"><h3>Backup &amp; restore</h3>
      <div class="vsub" style="margin:0 0 8px">This evaluation build stores the ledger in your browser. Export a signed snapshot for safekeeping; the hash chain lets anyone verify it wasn't altered.</div>
      <div class="row"><button class="btn2" id="bExport" ${have ? "" : "disabled"}>Export snapshot (JSON)</button>
        <label class="btn2">Import snapshot<input type="file" id="bImport" accept="application/json,.json" hidden></label>
        <button class="btn2 danger" id="bReset">Reset VAULT</button></div>
    </div>`;
    const $ = (id) => host.querySelector("#" + id);
    const qInit = $("qInit"); if (qInit) qInit.onclick = () => {
      try {
        const open = $("qOpen").value.trim(); const cents = toCents(open || "0");
        L = new Ledger({ policy: { minApprovers: 2, dualControl: true, tiers: [["25000.00", 3]] } });
        L.openAccount({ id: "bank", name: "Operating (bank)", type: "asset" });
        L.openAccount({ id: "equity", name: "Opening equity", type: "equity" });
        L.openAccount({ id: "clearing", name: "Outgoing clearing", type: "clearing" });
        if (cents > 0n) L.post({ memo: "opening balance", by: "setup", postings: [{ account: "bank", side: "debit", amount: cents }, { account: "equity", side: "credit", amount: cents }] });
        saveLedger(L); toast("Treasury initialized"); tab = "overview"; shell();
      } catch (e) { toast(e.message); }
    };
    const aAdd = $("aAdd"); if (aAdd) aAdd.onclick = () => {
      try { const name = $("aName").value.trim(); if (!name) return toast("Name required"); const id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + "-" + Math.random().toString(36).slice(2, 6); L.openAccount({ id, name, type: $("aType").value }); saveLedger(L); toast("Account added"); shell(); } catch (e) { toast(e.message); }
    };
    const pSave = $("pSave"); if (pSave) pSave.onclick = () => { try { const n = Math.max(1, parseInt($("pMin").value, 10) || 1); L.policy.minApprovers = n; saveLedger(L); toast("Policy saved"); } catch (e) { toast(e.message); } };
    const bExport = $("bExport"); if (bExport) bExport.onclick = () => { const blob = new Blob([JSON.stringify(L.snapshot(), null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "vault-snapshot.json"; document.body.appendChild(a); a.click(); setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 100); };
    const bImport = $("bImport"); if (bImport) bImport.onchange = (e) => { const f = e.target.files[0]; if (!f) return; const fr = new FileReader(); fr.onload = () => { try { const snap = JSON.parse(fr.result); const test = Ledger.load(snap); if (!test.verifyChain().ok) return toast("Refused: imported snapshot failed chain verification (tampered)."); L = test; saveLedger(L); toast("Imported and verified"); tab = "overview"; shell(); } catch (err) { toast("Import failed: " + err.message); } }; fr.readAsText(f); };
    const bReset = $("bReset"); if (bReset) bReset.onclick = () => { try { localStorage.removeItem(STORE); } catch (_) {} L = null; toast("VAULT reset"); tab = "setup"; shell(); };
  }

  shell();
}
