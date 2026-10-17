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

import { Ledger, toCents, fmtCents, screenTransfer } from "/js/vault/ledger.js?v=20261017c";
import { canDo, ROLES, ROLE_HELP } from "/js/vault/roles.js?v=20261012e";
import * as remote from "/js/vault/remote.js?v=20261012e";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.dnToast || window.showToast || (() => {}))(m); } catch (_) {} };
const STORE = "dn_vault_v1";
const WS = "dn_vault_ws";
const lsGet = (k) => { try { return localStorage.getItem(k); } catch (_) { return null; } };
const lsSet = (k, v) => { try { localStorage.setItem(k, v); } catch (_) {} };

function loadLedger() {
  try { const raw = localStorage.getItem(STORE); if (raw) return Ledger.load(JSON.parse(raw)); } catch (_) {}
  return null;
}
function saveLedger(L) { try { localStorage.setItem(STORE, JSON.stringify(L.snapshot())); } catch (e) { toast("Could not save locally: " + e.message); } }

function injectStyle() {
  if (document.getElementById("vlt-style")) return;
  const s = document.createElement("style"); s.id = "vlt-style";
  s.textContent = `
  .vlt{width:100%;padding:4px 2px 48px;min-width:0;box-sizing:border-box}
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
  .vlt .vkpi .ksub{font-size:.68rem;color:var(--mut,#98a2b3);margin-top:3px;line-height:1.3}
  .vlt .vmut{font-weight:400;font-size:.8rem;color:var(--mut,#98a2b3)}
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
  .vlt .btn2{appearance:none;font:inherit;font-size:.82rem;font-weight:600;border:1px solid var(--bd,#d7deea);background:var(--card,#fff);color:inherit;border-radius:8px;padding:0 13px;cursor:pointer;height:36px;display:inline-flex;align-items:center;justify-content:center;box-sizing:border-box;line-height:1.2;white-space:nowrap;margin:0}
  .vlt input:not([type=checkbox]):not([type=radio]):not([type=file]),.vlt select{height:36px;min-height:36px;padding-block:0;margin:0!important}
  .vlt label.f,.vlt label.btn2{margin:0!important}.vlt label.btn2{letter-spacing:normal}
  .vlt .btn2:hover{background:rgba(47,95,255,.06);border-color:#9db4ff}
  .vlt .btn2.pri{background:#2552c6;border-color:#2552c6;color:#fff}.vlt .btn2.pri:hover{background:#1c45ad}
  .vlt .btn2.danger{color:#b00020;border-color:#e0a7b0}.vlt .btn2.danger:hover{background:rgba(176,0,32,.06)}
  .vlt .row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:10px}
  .vlt .pill{font-size:.72rem;font-weight:700;border-radius:999px;padding:2px 9px;color:#fff;display:inline-block;background:var(--c,#667085)}
  .vlt .mono{font-family:ui-monospace,monospace;font-size:11.5px;color:var(--mut,#8893a7);word-break:break-all}
  .vlt .flags{font-size:.76rem;color:#8a5a00;margin-top:4px}
  .vlt .empty{text-align:center;color:var(--mut,#8893a7);padding:28px 10px;font-size:.88rem}
  .vlt .vws{display:flex;flex-wrap:wrap;align-items:flex-end;gap:10px;margin:12px 0 4px}
  .vlt .vws label.f{flex:1 1 260px;max-width:420px}
  .vlt .venf{font-size:.74rem;font-weight:700;border-radius:999px;padding:0 11px;height:36px;display:inline-flex;align-items:center;box-sizing:border-box}
  .vlt .venf.on{color:#11643a;background:rgba(26,127,55,.12);border:1px solid rgba(26,127,55,.35)}
  .vlt .venf.off{color:#7a5b00;background:rgba(245,158,11,.14);border:1px solid #f0c36d}
  .vlt .vnew{display:flex;flex-wrap:wrap;gap:8px;align-items:flex-end;margin:6px 0}
  .vlt .vnew label.f{flex:1 1 240px;max-width:360px}
  .vlt .vok2{color:#1a7f37}.vlt .vno{color:#b00020}
  `;
  document.head.appendChild(s);
}

const STATUS_COLOR = { pending: "#b58100", approved: "#2b6cb0", released: "#6b46c1", settled: "#1a7f37", rejected: "#b00020" };

export function renderVault(main) {
  injectStyle();
  // Workspace: "local" (this browser, controls not enforced) or a team vault id, whose
  // every operation is checked by the Darknode server.
  let ws = lsGet(WS) || "local";
  let L = null, team = null, vaults = [], tab = "overview", busy = false;
  let navTok = null;

  const who = (uid) => {
    if (!team) return uid;
    const m = team.members.find((x) => x.uid === uid);
    const label = m && m.label ? m.label : uid ? uid.slice(0, 8) + "…" : "";
    return label + (uid === team.uid ? " (you)" : "");
  };
  const may = (op) => !team || canDo(team.role, op);

  async function load() {
    const my = navTok = {};
    try { vaults = await remote.myVaults(); } catch (_) { vaults = []; }
    if (ws !== "local" && !vaults.some((v) => v.vid === ws)) ws = "local";
    if (ws === "local") { L = loadLedger(); team = null; }
    else {
      try {
        const [st, mem] = await Promise.all([remote.vaultState(ws), remote.listMembers(ws).catch(() => ({ members: [], log: [] }))]);
        if (my !== navTok) return;
        L = st.ledger ? Ledger.load(st.ledger) : null;
        const meta = vaults.find((v) => v.vid === ws);
        team = { vid: ws, name: meta ? meta.name : ws, role: st.role, uid: st.uid, audit: st.audit || [], auditCount: st.auditCount || 0, auditHead: st.auditHead || "", members: mem.members, log: mem.log };
      } catch (e) {
        toast("Could not open the team vault: " + e.message);
        ws = "local"; L = loadLedger(); team = null;
      }
    }
    if (my !== navTok) return;
    if (!team && tab === "team") tab = "overview";
    shell();
  }

  // Runs one operation: on the server for a team vault, in this browser otherwise.
  async function act(op, args, local, okMsg, nextTab) {
    if (busy) return;
    if (team) {
      busy = true;
      try { const r = await remote.vaultOp(team.vid, op, args); if (okMsg) toast(okMsg); if (nextTab) tab = nextTab; await load(); return r.result; }
      catch (e) { toast(e.message); }
      finally { busy = false; }
      return;
    }
    try { const r = local(); saveLedger(L); if (okMsg) toast(okMsg); if (nextTab) tab = nextTab; shell(); return r; }
    catch (e) { toast(e.message); }
  }

  const shell = () => {
    if (!main.isConnected) return;
    const tabs = ["overview:Overview", "move:Move funds", "approvals:Approvals", "audit:Audit log", "reconcile:Reconcile", "setup:Setup"];
    if (team) tabs.push("team:Team");
    main.innerHTML = `
    <div class="vlt">
      <div class="vhd"><h1>VAULT</h1><span class="vtag">Treasury &amp; Safeguarding</span></div>
      <div class="vsub">A record-keeping and controls tool for a company's treasury: a double-entry ledger with dual approvals and a
        tamper-evident audit chain. You type the figures in; VAULT keeps them honest and lets you reconcile them against statements you import.</div>
      <div class="vws">
        <label class="f">Workspace<select id="vWs">
          <option value="local"${ws === "local" ? " selected" : ""}>This browser only (local)</option>
          ${vaults.map((v) => `<option value="${esc(v.vid)}"${v.vid === ws ? " selected" : ""}>${esc(v.name)} (team, ${esc(v.role)})</option>`).join("")}
        </select></label>
        <button class="btn2" id="vNew">New team vault</button>
        ${team ? `<span class="venf on">Server-enforced</span>` : `<span class="venf off">Local only: controls not enforced</span>`}
      </div>
      <div class="vnew" id="vNewForm" hidden>
        <label class="f">Team vault name<input id="vNewName" maxlength="80" placeholder="e.g. Operating treasury"></label>
        <button class="btn2 pri" id="vNewGo">Create</button>
      </div>
      <div class="vbad"><b>These are figures you type in — not real money, and not a live bank balance.</b></div>
      ${team ? `<div class="vbanner">Team vault <b>${esc(team.name)}</b>. You are signed in as <b>${esc(who(team.uid))}</b> with the <b>${esc(team.role)}</b> role.
        Every movement, approval, release and posting is checked by the Darknode server: your identity comes from your sign-in, the
        approval and no-overdraft rules run on the server, and every attempt (allowed or refused) is written to a tamper-evident audit
        chain. VAULT still holds no money and is <b>connected to no bank</b>; a figure stays an unverified <b>book</b> entry until you
        reconcile it against a bank statement you import.</div>`
      : `<div class="vbanner">VAULT holds no money, is <b>connected to no bank</b>, and reads no account. Everything below is a
        bookkeeping entry you typed on this device, stored only in this browser, where anyone with the device can change it: the approval
        rules here are a preview, not a control. A figure stays an unverified <b>book</b> entry until you reconcile it against a real bank
        statement you import on the Reconcile tab. VAULT is not a bank, custodian, or money transmitter and never collects deposits.
        For enforced controls, create a <b>team vault</b>.</div>`}
      <div class="vtabs" id="vtabs">
        ${tabs.map((t) => { const [id, label] = t.split(":"); return `<button class="vtab${id === tab ? " on" : ""}" data-tab="${id}">${esc(label)}</button>`; }).join("")}
      </div>
      <div id="vbody"></div>
    </div>`;
    main.querySelectorAll(".vtab").forEach((b) => b.onclick = () => { tab = b.dataset.tab; shell(); });
    main.querySelector("#vWs").onchange = (e) => { ws = e.target.value; lsSet(WS, ws); tab = "overview"; main.querySelector("#vbody").innerHTML = `<div class="vcard"><div class="empty">Loading…</div></div>`; load(); };
    main.querySelector("#vNew").onclick = () => {
      if (!remote.me()) return toast("Sign in to create a team vault.");
      const f = main.querySelector("#vNewForm"); f.hidden = !f.hidden; if (!f.hidden) main.querySelector("#vNewName").focus();
    };
    main.querySelector("#vNewGo").onclick = async () => {
      const name = main.querySelector("#vNewName").value.trim();
      if (!name) return toast("Name the vault");
      try { ws = await remote.createVault(name); lsSet(WS, ws); tab = "setup"; toast("Team vault created. Initialize it to start."); await load(); }
      catch (e) { toast("Could not create the vault: " + e.message); }
    };
    body();
  };

  const body = () => {
    const host = main.querySelector("#vbody");
    if (!L && tab !== "setup" && tab !== "team" && tab !== "overview") { host.innerHTML = `<div class="vcard"><div class="empty">This vault is not initialized yet. Go to <b>Setup</b> to create accounts and opening balances.</div></div>`; return; }
    if (tab === "overview") renderOverview(host);
    else if (tab === "move") renderMove(host);
    else if (tab === "approvals") renderApprovals(host);
    else if (tab === "audit") renderAudit(host);
    else if (tab === "reconcile") renderReconcile(host);
    else if (tab === "team") renderTeam(host);
    else renderSetup(host);
  };

  // --- Overview ---
  function renderOverview(host) {
    const D = "\u2014";
    if (!L || !L.journal.length) {
      const accts = L ? L.accounts.size : 0;
      host.innerHTML = `<div class="vkpis">
        ${kpi("Book value (unverified)", D, "nothing entered yet")}
        ${kpi("Bank-confirmed", D)}
        ${kpi("Accounts", accts ? String(accts) : D)}
        ${kpi("Journal entries", D)}
        ${kpi("Pending movements", L && L.transfers.size ? String([...L.transfers.values()].filter((t) => t.status === "pending" || t.status === "approved").length) : D)}
        ${kpi("Trial balance", D)}
        ${kpi("Audit chain", D)}
        ${team ? kpi("Enforcement", `<span class="vok">Server</span>`, team.auditCount + " audited actions") : kpi("Enforcement", `<span style="color:#8a5a00">Local only</span>`, "controls not enforced")}
      </div>
      <div class="vcard"><div class="empty">No figures yet. ${L ? "Record an opening entry or a movement to see balances here." : "Go to <b>Setup</b> to create your accounts and enter your own opening balance."}</div></div>`;
      return;
    }
    const tb = L.trialBalance();
    const chain = L.verifyChain();
    const accts = [...L.accounts.values()];
    // Book value = funds held per the books: asset + omnibus balances only.
    // Expense (a cost, not value held) and clearing (in-transit) are debit-normal
    // too but must not inflate the headline position.
    const total = accts.filter((a) => a.type === "asset" || a.type === "omnibus").reduce((s, a) => s + L.balance(a.id).balance, 0n);
    const pending = [...L.transfers.values()].filter((t) => t.status === "pending" || t.status === "approved");
    const movements = [...L.transfers.values()].filter((t) => t.status !== "rejected");
    const settled = movements.filter((t) => t.status === "settled");
    let html = "";
    if (!chain.ok) html += `<div class="vbad">INTEGRITY ALERT: the audit chain failed verification at entry #${chain.brokenAt}. The ledger may have been altered outside VAULT. Do not trust these figures until investigated.</div>`;
    html += `<div class="vkpis">
      ${kpi("Book value (unverified)", fmtCents(total), "figures you entered")}
      ${kpi("Bank-confirmed", movements.length ? `${settled.length}/${movements.length}` : D, "movements reconciled to a statement")}
      ${kpi("Accounts", String(accts.length))}
      ${kpi("Journal entries", String(L.journal.length))}
      ${kpi("Pending movements", pending.length ? String(pending.length) : D)}
      ${kpi("Trial balance", tb.balanced ? `<span class="vok">Balanced</span>` : `<span style="color:#b00020">OFF by ${esc(fmtCents(tb.debits - tb.credits))}</span>`, "internal consistency, not bank truth")}
      ${kpi("Audit chain", chain.ok ? `<span class="vok">Verified</span>` : `<span style="color:#b00020">BROKEN</span>`)}
      ${team ? kpi("Enforcement", `<span class="vok">Server</span>`, team.auditCount + " audited actions") : kpi("Enforcement", `<span style="color:#8a5a00">Local only</span>`, "controls not enforced")}
    </div>`;
    html += `<div class="vcard"><h3>Book balances <span class="vmut">— entered figures, not confirmed against any bank</span></h3>${accts.length ? `<table><thead><tr><th>Account</th><th>Type</th><th class="num">Debits</th><th class="num">Credits</th><th class="num">Book balance</th></tr></thead><tbody>${accts.map((a) => { const b = L.balance(a.id); return `<tr><td>${esc(a.name)}</td><td>${esc(a.type)}</td><td class="num">${esc(fmtCents(b.debits))}</td><td class="num">${esc(fmtCents(b.credits))}</td><td class="num"><b>${esc(fmtCents(b.balance))}</b></td></tr>`; }).join("")}</tbody></table>` : `<div class="empty">No accounts.</div>`}</div>`;
    host.innerHTML = html;
  }
  const kpi = (k, v, sub) => `<div class="vkpi"><div class="k">${esc(k)}</div><div class="v">${v}</div>${sub ? `<div class="ksub">${esc(sub)}</div>` : ""}</div>`;

  // --- Move funds (create a transfer instruction) ---
  function renderMove(host) {
    if (!may("createTransfer")) { host.innerHTML = `<div class="vcard"><div class="empty">Your role (${esc(team.role)}) cannot create movements.</div></div>`; return; }
    const accts = [...L.accounts.values()];
    const opt = (a) => `<option value="${esc(a.id)}">${esc(a.name)} (${esc(a.type)})</option>`;
    host.innerHTML = `<div class="vcard"><h3>New fund movement</h3>
      <div class="vgrid">
        <label class="f">From account<select id="mFrom">${accts.map(opt).join("")}</select></label>
        <label class="f">To account<select id="mTo">${accts.map(opt).join("")}</select></label>
        <label class="f">Amount (USD)<input id="mAmt" placeholder="Amount" inputmode="decimal"></label>
        <label class="f">Payee (optional)<input id="mPayee" placeholder="vendor / beneficiary"></label>
        ${team ? "" : `<label class="f">Initiated by<input id="mBy" placeholder="your user id"></label>`}
        <label class="f">Memo<input id="mMemo" placeholder="what is this for"></label>
      </div>
      <div class="row"><button class="btn2 pri" id="mCreate">Create movement (requires approval)</button></div>
      <div class="flags" id="mScreen"></div>
      <div class="vsub" style="margin-top:8px">A movement records a ledger entry only — no real money moves. It posts nothing until ${L.policy.minApprovers} distinct people (never the initiator) approve it and it is released, and VAULT refuses to release more than the source account's book balance shows.${team ? " You are recorded as the initiator from your sign-in." : ""}</div>
    </div>`;
    const $ = (id) => host.querySelector("#" + id);
    const by = () => team ? team.uid : $("mBy").value.trim();
    // live screen preview
    const preview = () => {
      try { const amt = toCents($("mAmt").value || "0"); const s = screenTransfer(L, { from: $("mFrom").value, amount: amt, payee: $("mPayee").value, by: by() }); $("mScreen").innerHTML = s.flags.length ? "Pre-flight screen (" + s.level + "): " + s.flags.map(esc).join(" · ") : ""; } catch (_) { $("mScreen").innerHTML = ""; }
    };
    ["mAmt", "mPayee", "mFrom"].forEach((id) => $(id).addEventListener("input", preview));
    $("mCreate").onclick = () => {
      const a = { from: $("mFrom").value, to: $("mTo").value, amount: $("mAmt").value, payee: $("mPayee").value.trim(), memo: $("mMemo").value.trim() };
      act("createTransfer", a, () => L.createTransfer({ id: "t" + Date.now().toString(36), ...a, by: by(), ts: Date.now() }), "Movement created — awaiting approval", "approvals");
    };
  }

  // --- Approvals queue ---
  function renderApprovals(host) {
    const open = [...L.transfers.values()].filter((t) => t.status === "pending" || t.status === "approved");
    if (!open.length) { host.innerHTML = `<div class="vcard"><div class="empty">No movements awaiting approval or release.</div></div>`; return; }
    host.innerHTML = open.map((t) => {
      const c = STATUS_COLOR[t.status];
      const mine = team && t.by === team.uid;
      const canAp = t.status === "pending" && may("approve") && !mine && !(team && t.approvers.includes(team.uid));
      const canRl = t.status === "approved" && may("release") && !mine;
      return `<div class="vcard" data-t="${esc(t.id)}">
        <div style="display:flex;flex-wrap:wrap;gap:10px;align-items:baseline">
          <span class="pill" style="--c:${c}">${esc(t.status)}</span>
          <b>${esc(fmtCents(t.amount))}</b>
          <span class="vsub" style="margin:0">${esc(L.accounts.get(t.from) ? L.accounts.get(t.from).name : t.from)} &rarr; ${esc(L.accounts.get(t.to) ? L.accounts.get(t.to).name : t.to)}${t.payee ? " · " + esc(t.payee) : ""}</span>
          <span class="vsub" style="margin:0 0 0 auto">by ${esc(who(t.by))} · approvals ${t.approvers.length}/${t.required}</span>
        </div>
        ${t.memo ? `<div class="vsub" style="margin:4px 0">${esc(t.memo)}</div>` : ""}
        ${t.screen && t.screen.flags.length ? `<div class="flags">Screen (${esc(t.screen.level)}): ${t.screen.flags.map(esc).join(" · ")}</div>` : ""}
        ${t.approvers.length ? `<div class="vsub" style="margin:4px 0">Approved by: ${t.approvers.map((a) => esc(who(a))).join(", ")}</div>` : ""}
        ${mine ? `<div class="vsub" style="margin:4px 0">You created this movement, so someone else must approve and release it.</div>` : ""}
        <div class="row">
          ${team ? "" : `<input placeholder="approver / releaser id" class="apId" style="max-width:220px">`}
          ${canAp || (!team && t.status === "pending") ? `<button class="btn2 aApprove">Approve</button>` : ""}
          ${canRl || (!team && t.status === "approved") ? `<button class="btn2 pri aRelease">Release (post)</button>` : ""}
          ${may("reject") ? `<button class="btn2 danger aReject">Reject</button>` : ""}
        </div>
      </div>`;
    }).join("");
    host.querySelectorAll("[data-t]").forEach((card) => {
      const id = card.dataset.t;
      const who2 = () => team ? team.uid : (card.querySelector(".apId").value || "").trim();
      const need = (m) => { if (!who2()) { toast(m); return false; } return true; };
      const ap = card.querySelector(".aApprove"); if (ap) ap.onclick = () => need("Enter the approver id") && act("approve", { id }, () => L.approve(id, who2()), "Approval recorded");
      const rl = card.querySelector(".aRelease"); if (rl) rl.onclick = () => need("Enter the releaser id") && act("release", { id }, () => L.release(id, who2(), Date.now()), "Released and posted to the ledger");
      const rj = card.querySelector(".aReject"); if (rj) rj.onclick = () => act("reject", { id, reason: "" }, () => L.reject(id, who2(), ""), "Movement rejected");
    });
  }

  // --- Audit log ---
  function renderAudit(host) {
    const chain = L.verifyChain();
    const ok = (n) => `<span class="vok">Verified — ${n} entries, intact.</span>`;
    let html = `<div class="vcard"><h3>Tamper-evident audit chain</h3>
      <div class="row"><button class="btn2" id="aVerify">${team ? "Verify on the server" : "Verify chain now"}</button>
      <span id="aVerOut">${chain.ok ? ok(L.journal.length) : `<span style="color:#b00020">BROKEN at entry #${chain.brokenAt}.</span>`}</span></div></div>`;
    if (team) html += `<div class="vcard"><h3>Server audit log <span class="vmut">— every attempt, allowed or refused (latest ${team.audit.length} of ${team.auditCount})</span></h3>${team.audit.length ? `<table><thead><tr><th>#</th><th>When</th><th>Who</th><th>Action</th><th>Result</th><th>Hash</th></tr></thead><tbody>${team.audit.map((a) => `<tr><td>${a.n}</td><td>${esc(new Date(a.ts).toLocaleString())}</td><td>${esc(who(a.by))}<div class="vmut">${esc(a.role)}</div></td><td>${esc(a.op)}</td><td>${a.ok ? `<span class="vok2">Allowed</span>` : `<span class="vno">Refused</span><div class="vmut">${esc(a.error || "")}</div>`}</td><td class="mono">${esc(String(a.hash).slice(0, 12))}…</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No actions yet.</div>`}</div>`;
    html += `<div class="vcard"><h3>Journal (append-only)</h3>${L.journal.length ? `<table><thead><tr><th>#</th><th>Memo</th><th>Postings</th><th class="num">Amount</th><th>Hash</th></tr></thead><tbody>${L.journal.map((e) => `<tr><td>${e.seq}</td><td>${esc(e.memo)}${team && e.by ? `<div class="vmut">by ${esc(who(e.by))}</div>` : ""}</td><td class="mono">${e.postings.map((p) => `${esc(p.side === "debit" ? "DR" : "CR")} ${esc(L.accounts.get(p.account) ? L.accounts.get(p.account).name : p.account)}`).join("<br>")}</td><td class="num">${esc(fmtCents(e.postings.filter((p) => p.side === "debit").reduce((s, p) => s + p.amount, 0n)))}</td><td class="mono">${esc(e.hash.slice(0, 12))}…</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No entries yet.</div>`}</div>`;
    host.innerHTML = html;
    host.querySelector("#aVerify").onclick = async () => {
      const out = host.querySelector("#aVerOut");
      if (!team) { const v = L.verifyChain(); out.innerHTML = v.ok ? ok(L.journal.length) : `<span style="color:#b00020">BROKEN at entry #${v.brokenAt}.</span>`; return; }
      out.textContent = "Verifying…";
      try {
        const v = await remote.vaultVerify(team.vid);
        out.innerHTML = (v.ledger && v.ledger.ok ? `<span class="vok">Ledger chain intact.</span>` : `<span style="color:#b00020">Ledger chain BROKEN${v.ledger ? " at entry #" + v.ledger.brokenAt : ""}.</span>`) + " " +
          (v.audit.ok ? `<span class="vok">Audit chain intact (${v.audit.entries} entries).</span>` : `<span style="color:#b00020">Audit chain BROKEN at #${v.audit.brokenAt}.</span>`);
      } catch (e) { out.textContent = e.message; }
    };
  }

  // --- Reconcile ---
  function renderReconcile(host) {
    host.innerHTML = `<div class="vcard"><h3>Reconcile against your bank statement</h3>
      <div class="vsub" style="margin:0 0 8px">Paste bank lines as <code>amount,reference</code> (one per line). VAULT matches released movements to real bank debits and flags anything unmatched on either side — the gap where fraud and errors hide.</div>
      <textarea id="rLines" placeholder="amount,reference (one bank line per row)"></textarea>
      <div class="row"><button class="btn2 pri" id="rRun" ${may("reconcile") ? "" : "disabled"}>Reconcile</button>${may("reconcile") ? "" : `<span class="vmut">Your role cannot reconcile.</span>`}</div>
      <div id="rOut" style="margin-top:12px"></div>
    </div>`;
    host.querySelector("#rRun").onclick = async () => {
      const lines = host.querySelector("#rLines").value.trim().split(/\n+/).filter(Boolean).map((l) => { const [amt, ...ref] = l.split(","); return { amount: amt.trim(), ref: ref.join(",").trim() }; });
      let res;
      if (team) {
        try { res = (await remote.vaultOp(team.vid, "reconcile", { lines })).result; } catch (e) { return toast(e.message); }
      } else {
        try { res = L.reconcile(lines); } catch (e) { return toast(e.message); }
        saveLedger(L);
      }
      host.querySelector("#rOut").innerHTML = `
        <div class="vkpis"><div class="vkpi"><div class="k">Matched</div><div class="v vok">${res.matched.length}</div></div>
        <div class="vkpi"><div class="k">Unmatched (bank)</div><div class="v" style="${res.unmatchedBank.length ? "color:#b00020" : ""}">${res.unmatchedBank.length}</div></div>
        <div class="vkpi"><div class="k">Unmatched (ledger)</div><div class="v" style="${res.unmatchedLedger.length ? "color:#b00020" : ""}">${res.unmatchedLedger.length}</div></div></div>
        ${res.unmatchedBank.length ? `<div class="vcard"><h3>On the bank, not matched in VAULT</h3><table><tbody>${res.unmatchedBank.map((b) => `<tr><td class="num">${esc(b.amount)}</td><td class="mono">${esc(b.ref)}</td></tr>`).join("")}</tbody></table></div>` : ""}
        ${res.unmatchedLedger.length ? `<div class="vcard"><h3>Released in VAULT, not seen at the bank</h3><table><tbody>${res.unmatchedLedger.map((t) => `<tr><td>${esc(t.id)}</td><td class="num">${esc(t.amount)}</td></tr>`).join("")}</tbody></table></div>` : ""}`;
      if (team) { const keep = host.querySelector("#rOut").innerHTML; await load(); if (tab === "reconcile") main.querySelector("#rOut").innerHTML = keep; }
    };
  }

  // --- Team (server-enforced vaults only) ---
  function renderTeam(host) {
    const owner = team.role === "owner";
    const roleOpts = (sel) => ROLES.map((r) => `<option value="${r}"${r === sel ? " selected" : ""}>${r}</option>`).join("");
    host.innerHTML = `
    <div class="vcard"><h3>Your sign-in</h3>
      <div class="vsub" style="margin:0 0 8px">To be added to a team vault, give its owner your user id.</div>
      <div class="row" style="margin:0"><span class="mono" id="tMe">${esc(team.uid)}</span><button class="btn2" id="tCopy">Copy user id</button></div>
    </div>
    <div class="vcard"><h3>Members</h3>
      <table><thead><tr><th>Member</th><th>User id</th><th>Role</th>${owner ? "<th></th>" : ""}</tr></thead><tbody>
      ${team.members.map((m) => `<tr data-uid="${esc(m.uid)}"><td>${esc(m.label || "—")}${m.uid === team.uid ? ` <span class="vmut">(you)</span>` : ""}</td><td class="mono">${esc(m.uid)}</td>
        <td>${owner && m.uid !== team.uid ? `<select class="tRole">${roleOpts(m.role)}<option value="removed"${m.role === "removed" ? " selected" : ""}>removed</option></select>` : esc(m.role)}</td>
        ${owner ? `<td>${m.uid !== team.uid ? `<button class="btn2 tSave">Save</button>` : ""}</td>` : ""}</tr>`).join("")}
      </tbody></table>
      ${owner ? `<div class="vgrid" style="margin-top:12px">
        <label class="f">User id<input id="tUid" placeholder="their user id" maxlength="128"></label>
        <label class="f">Name or email (shown to the team)<input id="tLabel" maxlength="120" placeholder="e.g. user01, finance"></label>
        <label class="f">Role<select id="tNewRole">${roleOpts("approver")}</select></label>
      </div>
      <div class="row"><button class="btn2 pri" id="tAdd">Add member</button></div>
      <div class="vsub" style="margin-top:6px">Membership is enforced by the database rules: only an owner can change roles, never their own, and every change is logged below.</div>` : ""}
    </div>
    <div class="vcard"><h3>What each role can do</h3><table><tbody>${ROLES.map((r) => `<tr><td><b>${r}</b></td><td>${esc(ROLE_HELP[r])}</td></tr>`).join("")}</tbody></table></div>
    <div class="vcard"><h3>Membership log <span class="vmut">— append-only</span></h3>${team.log.length ? `<table><thead><tr><th>When</th><th>Changed by</th><th>Member</th><th>New role</th></tr></thead><tbody>${team.log.map((l) => `<tr><td>${l.ts ? esc(new Date(l.ts).toLocaleString()) : ""}</td><td>${esc(who(l.by))}</td><td>${esc(who(l.uid))}</td><td>${esc(l.role)}</td></tr>`).join("")}</tbody></table>` : `<div class="empty">No changes yet.</div>`}</div>`;
    host.querySelector("#tCopy").onclick = () => { try { navigator.clipboard.writeText(team.uid); toast("User id copied"); } catch (_) {} };
    const save = async (uid, role, label) => {
      try { await remote.setMember(team.vid, uid, role, label); toast("Membership updated"); await load(); }
      catch (e) { toast("Not allowed: " + e.message); }
    };
    host.querySelectorAll("tr[data-uid] .tSave").forEach((b) => b.onclick = () => {
      const tr = b.closest("tr"); const m = team.members.find((x) => x.uid === tr.dataset.uid);
      save(m.uid, tr.querySelector(".tRole").value, m.label);
    });
    const add = host.querySelector("#tAdd");
    if (add) add.onclick = () => {
      const uid = host.querySelector("#tUid").value.trim();
      if (!/^[A-Za-z0-9_-]{6,128}$/.test(uid)) return toast("Enter the person's user id (they can copy it from this tab)");
      save(uid, host.querySelector("#tNewRole").value, host.querySelector("#tLabel").value.trim());
    };
  }

  // --- Setup ---
  function renderSetup(host) {
    const have = !!L;
    if (team) return renderTeamSetup(host);
    host.innerHTML = `
    ${!have ? `<div class="vcard"><h3>Quick start</h3><div class="vsub" style="margin:0 0 8px">Create a standard chart of accounts: an Operating account (asset), an Opening equity account, and an Outgoing clearing account. The opening balance is a <b>book figure you type in</b> to start the ledger — not real money and not pulled from any bank.</div>
      <div class="vgrid"><label class="f">Opening book balance (USD)<input id="qOpen" placeholder="Amount" inputmode="decimal"></label>
        <label class="f">Minimum approvers<input id="pMin" type="number" min="1" max="10" inputmode="numeric" placeholder="1 to 10"></label>
        <label class="f">Higher tiers (optional)<input id="pTiers" placeholder="amount:approvers"></label></div>
      <div class="vsub" style="margin:6px 0 8px">Approvers: how many different people must approve each movement. Tiers, if any, raise that for larger amounts (amount:approvers, separated by commas).</div>
      <div class="row"><button class="btn2 pri" id="qInit">Initialize treasury</button></div></div>` : ""}
    <div class="vcard"><h3>Add account</h3>
      <div class="vgrid">
        <label class="f">Name<input id="aName" placeholder="e.g. Payroll (bank)"></label>
        <label class="f">Type<select id="aType">${ACCT_TYPES}</select></label>
      </div>
      <div class="row"><button class="btn2" id="aAdd" ${have ? "" : "disabled"}>Add account</button></div>
    </div>
    ${have ? `<div class="vcard"><h3>Policy</h3>
      <div class="vgrid">
        <label class="f">Minimum approvers<input id="pMin" type="number" min="1" max="10" value="${L.policy.minApprovers}"></label>
        <label class="f">Higher tiers (optional)<input id="pTiers" value="${esc(tierText(L))}" placeholder="amount:approvers"></label>
      </div>
      <div class="row"><button class="btn2" id="pSave">Save policy</button></div>
    </div>` : ""}
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
        L = new Ledger({ policy: { ...readPolicy(host), dualControl: true } });
        L.openAccount({ id: "bank", name: "Operating account", type: "asset" });
        L.openAccount({ id: "equity", name: "Opening equity", type: "equity" });
        L.openAccount({ id: "clearing", name: "Outgoing clearing", type: "clearing" });
        if (cents > 0n) L.post({ memo: "opening balance", by: "setup", postings: [{ account: "bank", side: "debit", amount: cents }, { account: "equity", side: "credit", amount: cents }] });
        saveLedger(L); toast("Treasury initialized"); tab = "overview"; shell();
      } catch (e) { toast(e.message); }
    };
    const aAdd = $("aAdd"); if (aAdd) aAdd.onclick = () => {
      try { const name = $("aName").value.trim(); if (!name) return toast("Name required"); const id = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") + "-" + Math.random().toString(36).slice(2, 6); L.openAccount({ id, name, type: $("aType").value }); saveLedger(L); toast("Account added"); shell(); } catch (e) { toast(e.message); }
    };
    const pSave = $("pSave"); if (pSave) pSave.onclick = () => { try { Object.assign(L.policy, readPolicy(host)); saveLedger(L); toast("Policy saved"); } catch (e) { toast(e.message); } };
    const bExport = $("bExport"); if (bExport) bExport.onclick = () => exportSnap();
    const bImport = $("bImport"); if (bImport) bImport.onchange = (e) => { const f = e.target.files[0]; if (!f) return; const fr = new FileReader(); fr.onload = () => { try { const snap = JSON.parse(fr.result); const test = Ledger.load(snap); if (!test.verifyChain().ok) return toast("Refused: imported snapshot failed chain verification (tampered)."); L = test; saveLedger(L); toast("Imported and verified"); tab = "overview"; shell(); } catch (err) { toast("Import failed: " + err.message); } }; fr.readAsText(f); };
    const bReset = $("bReset"); if (bReset) bReset.onclick = () => { try { localStorage.removeItem(STORE); } catch (_) {} L = null; toast("VAULT reset"); tab = "setup"; shell(); };
  }
  const exportSnap = () => { const blob = new Blob([JSON.stringify(L.snapshot(), null, 2)], { type: "application/json" }); const url = URL.createObjectURL(blob); const a = document.createElement("a"); a.href = url; a.download = "vault-snapshot.json"; document.body.appendChild(a); a.click(); setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 100); };

  function renderTeamSetup(host) {
    const have = !!L;
    const tiers = have ? tierText(L) : "";
    host.innerHTML = `
    ${!have ? `<div class="vcard"><h3>Initialize this team vault</h3>${may("init") ? `<div class="vsub" style="margin:0 0 8px">Creates an Operating account (asset), an Opening equity account and an Outgoing clearing account on the server. The opening balance is a <b>book figure you type in</b>, not real money.</div>
      <div class="vgrid"><label class="f">Opening book balance (USD)<input id="qOpen" placeholder="Amount" inputmode="decimal"></label>
        <label class="f">Minimum approvers<input id="pMin" type="number" min="1" max="10" inputmode="numeric" placeholder="1 to 10"></label>
        <label class="f">Higher tiers (optional)<input id="pTiers" placeholder="amount:approvers"></label></div>
      <div class="vsub" style="margin:6px 0 8px">Approvers: how many different people, never the initiator, must approve each movement. Tiers, if any, raise that for larger amounts (amount:approvers, separated by commas).</div>
      <div class="row"><button class="btn2 pri" id="qInit">Initialize on the server</button></div>` : `<div class="empty">Waiting for an owner to initialize this vault.</div>`}</div>` : ""}
    ${have && may("openAccount") ? `<div class="vcard"><h3>Add account</h3>
      <div class="vgrid">
        <label class="f">Name<input id="aName" maxlength="80" placeholder="e.g. Payroll (bank)"></label>
        <label class="f">Type<select id="aType">${ACCT_TYPES}</select></label>
      </div>
      <div class="row"><button class="btn2" id="aAdd">Add account</button></div></div>` : ""}
    ${have ? `<div class="vcard"><h3>Approval policy</h3>
      <div class="vgrid">
        <label class="f">Minimum approvers<input id="pMin" type="number" min="1" max="10" value="${L.policy.minApprovers}" ${may("setPolicy") ? "" : "disabled"}></label>
        <label class="f">Higher tiers (amount:approvers)<input id="pTiers" value="${esc(tiers)}" placeholder="amount:approvers" ${may("setPolicy") ? "" : "disabled"}></label>
      </div>
      ${may("setPolicy") ? `<div class="row"><button class="btn2" id="pSave">Save policy</button></div>` : ""}
      <div class="vsub" style="margin-top:6px">Dual control is always on for a team vault: the person who creates a movement can never approve or release it.</div></div>` : ""}
    ${have ? `<div class="vcard"><h3>Export</h3><div class="vsub" style="margin:0 0 8px">Download the ledger as JSON. The hash chain lets anyone check it was not altered.</div>
      <div class="row"><button class="btn2" id="bExport">Export snapshot (JSON)</button></div></div>` : ""}`;
    const $ = (id) => host.querySelector("#" + id);
    const qInit = $("qInit"); if (qInit) qInit.onclick = () => { let policy; try { policy = readPolicy(host); } catch (e) { return toast(e.message); } act("init", { opening: $("qOpen").value.trim(), policy }, null, "Team vault initialized", "overview"); };
    const aAdd = $("aAdd"); if (aAdd) aAdd.onclick = () => { const name = $("aName").value.trim(); if (!name) return toast("Name required"); act("openAccount", { name, type: $("aType").value }, null, "Account added"); };
    const pSave = $("pSave"); if (pSave) pSave.onclick = () => {
      let policy; try { policy = readPolicy(host); } catch (e) { return toast(e.message); }
      act("setPolicy", policy, null, "Policy saved");
    };
    const bExport = $("bExport"); if (bExport) bExport.onclick = () => exportSnap();
  }

  main.innerHTML = `<div class="vlt"><div class="vcard"><div class="empty">Loading VAULT…</div></div></div>`;
  load();
}

const tierText = (L) => (L.policy.tiers || []).map((t) => t[0] + ":" + t[1]).join(", ");

// Reads the approval policy the user typed. Nothing is assumed: approvers must be entered.
function readPolicy(host) {
  const n = Number(host.querySelector("#pMin").value.trim() || NaN);
  if (!Number.isInteger(n) || n < 1 || n > 10) throw new Error("Enter the minimum number of approvers (1 to 10)");
  const tiers = host.querySelector("#pTiers").value.split(",").map((x) => x.trim()).filter(Boolean).map((x) => {
    const [a, r] = x.split(":").map((y) => (y || "").trim());
    const req = Number(r);
    if (!a || toCents(a) <= 0n || !Number.isInteger(req) || req < 1 || req > 10) throw new Error("Each tier is amount:approvers, e.g. a positive amount and 1 to 10 approvers");
    return [a, req];
  });
  if (tiers.length > 10) throw new Error("At most 10 tiers");
  return { minApprovers: n, tiers };
}

const ACCT_TYPES = `<option value="asset">asset (bank / cash)</option><option value="clearing">clearing</option><option value="liability">liability</option><option value="customer">customer balance</option><option value="equity">equity</option><option value="income">income</option><option value="expense">expense</option>`;
