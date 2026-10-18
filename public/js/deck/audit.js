// Audit Log scene (Deck D6): the per-workspace, hash-chained record of every change to
// the shared Security Graph. Owner/admin only (the worker enforces it). Each entry commits
// to the one before it, so "Verify chain" can prove nothing has been altered or dropped.
import { auditAvailable, auditLog, auditVerify } from "./audit-client.js";

const S = { ctx: null, el: null, data: null, busy: false };
const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const toast = (m, t) => { try { S.ctx && S.ctx.toast && S.ctx.toast(m, t); } catch (_) {} };
const when = (ts) => { if (!ts) return "-"; const d = new Date(ts); return d.toLocaleString(undefined, { year: "numeric", month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }); };
const shortUid = (u) => (!u ? "unknown" : u.length > 12 ? u.slice(0, 6) + "…" + u.slice(-4) : u);

function injectStyle() {
  if (document.getElementById("audit-css")) return;
  const st = document.createElement("style"); st.id = "audit-css";
  st.textContent = `
.audit-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 14px;line-height:1.5}
.audit-bar{display:flex;gap:8px;align-items:center;margin:0 0 14px;flex-wrap:wrap}
.audit-btn{appearance:none;border:1px solid rgba(23,33,56,.16);background:#fff;border-radius:7px;font:inherit;font-size:12px;font-weight:600;color:#2a3450;padding:5px 11px;cursor:pointer}
.audit-btn:hover{border-color:var(--dk-acc,#2552c6);color:var(--dk-acc,#2552c6)}
.audit-stat{font-size:12.5px;color:#5a6680;margin-left:auto}
.audit-chain{font-size:12.5px;font-weight:700;border-radius:20px;padding:2px 10px}
.audit-chain.ok{background:rgba(18,168,95,.12);color:#0b7a43}
.audit-chain.bad{background:rgba(198,40,40,.12);color:#c62828}
.audit-tbl{width:100%;border-collapse:collapse;font-size:12.5px}
.audit-tbl th{text-align:left;color:#5a6680;font-weight:600;padding:7px 10px;border-bottom:1px solid rgba(23,33,56,.12);white-space:nowrap}
.audit-tbl td{padding:7px 10px;border-bottom:1px solid rgba(23,33,56,.07);vertical-align:top}
.audit-op{font-weight:600;color:#141c2e}
.audit-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:#5a6680}
.audit-off{font-size:12.5px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:11px 13px;line-height:1.5}
.audit-empty{color:#5a6680;font-size:13px;padding:16px 2px}
`;
  document.head.appendChild(st);
}

export function mountAudit(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el;
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>Audit Log</h1><p>Every change to this workspace's Security Graph, newest first. Entries are hash-chained — each one commits to the previous — so a single altered or removed record can be detected. Readable by owners and admins.</p></div></div>
    <div class="dk-ovp" id="auditBody"><div class="dk-loading"><span class="sp"></span>Loading…</div></div>`;
  load();
}
export function repaintAudit() {}

async function load() {
  const box = S.el && S.el.querySelector("#auditBody"); if (!box) return;
  if (!auditAvailable()) { box.innerHTML = `<div class="audit-off">The audit log needs the cloud proxy, which this build has not configured. Nothing to show yet.</div>`; return; }
  try { S.data = await auditLog(); paint(); }
  catch (e) { box.innerHTML = `<div class="audit-off">${E(e.message || String(e))}</div>`; }
}

function paint(chain) {
  const box = S.el && S.el.querySelector("#auditBody"); if (!box || !S.data) return;
  const entries = S.data.entries || [];
  const chainHtml = chain ? `<span class="audit-chain ${chain.ok ? "ok" : "bad"}">${chain.ok ? "Chain verified · " + chain.entries + " entries" : "Chain broken at entry " + chain.brokenAt}</span>` : "";
  const rows = entries.length ? entries.map((e) => `<tr>
      <td>${E(when(e.ts))}</td>
      <td title="${E(e.uid || "")}">${E(shortUid(e.uid))}</td>
      <td class="audit-op">${E(e.op || "-")}</td>
      <td>${Number(e.entities) || 0} entit${(Number(e.entities) || 0) === 1 ? "y" : "ies"}${e.relationships ? ", " + e.relationships + " link" + (e.relationships === 1 ? "" : "s") : ""}</td>
      <td class="audit-mono">rev ${Number(e.rev) || 0}</td>
      <td class="audit-mono" title="${E((e.hash || "").slice(0, 32))}">${E((e.hash || "").slice(0, 10))}</td>
    </tr>`).join("") : "";

  box.innerHTML = `
    <div class="audit-bar">
      <button class="audit-btn" id="auditVerify">Verify chain</button>
      <button class="audit-btn" id="auditRefresh">Refresh</button>
      ${chainHtml}
      <span class="audit-stat">${S.data.count || 0} total change${(S.data.count || 0) === 1 ? "" : "s"}${entries.length < (S.data.count || 0) ? " · showing latest " + entries.length : ""}</span>
    </div>
    ${entries.length ? `<table class="audit-tbl"><thead><tr><th>When</th><th>Who</th><th>Action</th><th>Changed</th><th>Revision</th><th>Hash</th></tr></thead><tbody>${rows}</tbody></table>`
      : `<div class="audit-empty">No changes recorded yet. Entries appear here as tools write findings and entities into this workspace's graph.</div>`}`;

  box.querySelector("#auditRefresh").onclick = load;
  box.querySelector("#auditVerify").onclick = verify;
}

async function verify() {
  if (S.busy) return; S.busy = true;
  toast("Verifying the audit chain…");
  try {
    const v = await auditVerify();
    paint(v);
    toast(v.ok ? "Chain verified: " + v.entries + " entries intact." : "Chain is broken at entry " + v.brokenAt + ".", v.ok ? "ok" : "error");
  } catch (e) { toast(e.message || "Verify failed.", "error"); }
  finally { S.busy = false; }
}
