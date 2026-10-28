// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Deck Findings scene as a work queue: queue views with live counts, owner and SLA due
// columns, a role-aware bulk bar (assign / status with resolution / due date / risk
// exception / tickets), a full finding detail page (severity override, exception panel,
// tickets, comments and a readable timeline), saved views, and the workspace SLA policy
// section of Settings. The workflow rules live in core/workflow.js; this file is the UI.
//
//   mountFindingsQueue(el, ctx)      render the scene into el
//   repaintFindingsQueue(m)          repaint after a graph change (m = security-graph module)
//   openFindingDetail(id, ctx?)      show one finding's detail page
//   renderSlaSettings(gridEl, ctx)   append the SLA policy panel to the Settings grid
//
// ctx (from deck-ui.js): { withGraph, esc, IC, IC_SEARCH, SEV_C, ST_C, toast, openTool,
//   toolLabel, openEntityDrawer, user, capword, agoISO, dl, findings, activeWorkspace,
//   listMembers, isActive }
//
// Every string that came from a tool (names, descriptions, evidence, comments) is escaped.

import {
  SLA_DEFAULTS, SLA_SOURCES, VIEWS, VIEW_LABEL, RESOLUTIONS, SEVERITY_LEVELS, WORKFLOW_STATUSES, COMMENT_MAX,
  DAY_MS, EXCEPTION_MAX_DAYS, normalizePolicy, slaState, applyChange, applyBulk, inView, timeline, isKnownExploited,
} from "../core/workflow.js";
import { getSlaPolicy, setConfig, SLA_CONFIG } from "../core/ws-config.js";
import { canDo } from "../core/workspace-roles.js";
import { isSimulated } from "../core/posture.js";
import { playbookFor } from "../core/playbooks.js";
import { openTicketExport } from "./ticket-export.js";
import {
  RESOLUTION_LABEL, dueChip, slaBasis, urgencySort, cleanTitle, memberName, timelineSentences, evidenceLines,
  summarizeBulk, dateInputToMs, localDay, exceptionMaxDay, normalizeSaved, upsertSaved, removeSaved, isOpenStatus, statusText,
} from "../core/queue-format.js";

const KEV_URL = "/data/feeds/cisa-kev-index.json";
const LS_VIEW = "dn_deck_fview__";      // + workspace id: last queue view
const LS_SAVED = "dn_deck_fviews__";    // + uid + "__" + workspace id: saved views
const LS_GROUP = "dn_deck_fgroup__";    // + workspace id: queue group-by dimension
// Group-by dimensions. Only unambiguous, one-finding-one-group keys (asset/control
// grouping is deferred: a finding can touch several assets, so it needs a design choice).
export const GROUPS = ["none", "source", "severity", "owner", "status"];
const GROUP_LABEL = { none: "No grouping", source: "Source tool", severity: "Severity", owner: "Owner", status: "Status" };
const SLA_KEYS = ["critical", "high", "medium", "low", "info", "kev"];
const SLA_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info", kev: "Known exploited (CISA KEV)" };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info" };

const S = {
  ctx: null, el: null, wsk: null,
  f: { q: "", severity: "", status: "", source: "", sim: false },
  view: "open", group: "none", sel: new Set(), rows: [], saved: [], savedName: "",
  detailId: null, scrollTop: 0, scrollEl: null,
  policy: normalizePolicy(SLA_DEFAULTS), policyLoaded: false,
  role: null, roleErr: "", members: [], teamP: null,
  kev: null, kevState: "idle", kevP: null,
};

// ---------- small utilities ----------
const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const toast = (m) => { try { (S.ctx && S.ctx.toast ? S.ctx.toast : (x) => (window.showToast || (() => {}))(x))(m); } catch (_) {} };
const cap = (s) => (S.ctx && S.ctx.capword ? S.ctx.capword(s) : (s ? s.charAt(0).toUpperCase() + s.slice(1) : "-"));
const lsGet = (k) => { try { return localStorage.getItem(k); } catch (_) { return null; } };
const lsSet = (k, v) => { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch (_) {} };
const myUid = () => (S.ctx && S.ctx.user && S.ctx.user.uid) || "";
const teamWid = () => { const w = S.ctx && S.ctx.activeWorkspace ? S.ctx.activeWorkspace() : null; return w && w !== myUid() ? w : null; };
const wsKey = () => teamWid() || myUid() || "personal";
const isPersonal = () => !teamWid();
const roleNow = () => (isPersonal() ? "owner" : S.role || "viewer");
const canWrite = () => isPersonal() || (S.role != null && canDo(S.role, "write"));
const canEditSla = () => { const r = roleNow(); return r === "owner" || r === "admin"; }; // firestore.rules: config is owner/admin-write
const fmtDay = (ms) => { try { return new Date(ms).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" }); } catch (_) { return localDay(ms); } };
const fmtWhen = (ms) => { try { return new Date(ms).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }); } catch (_) { return String(ms); } };
const toMs = (v) => (typeof v === "number" ? v : typeof v === "string" && v ? Date.parse(v) : NaN);
const sevC = (s) => (S.ctx && S.ctx.SEV_C && S.ctx.SEV_C[s]) || "#8a93a6";
const stC = (s) => (S.ctx && S.ctx.ST_C && S.ctx.ST_C[s]) || "#8a93a6";
const pill = (c, t) => `<span class="pill fq-pill" style="--c:${c}">${E(t)}</span>`;
const typing = () => { const a = document.activeElement; return !!(a && S.el && S.el.contains(a) && /^(INPUT|TEXTAREA|SELECT)$/.test(a.tagName)); };
const slaOf = (e, now) => slaState(e, S.policy, now, { kevSet: S.kev || undefined });
const viewOpts = (now) => ({ uid: myUid(), now, policy: S.policy, kevSet: S.kev || undefined });
const nameOfFor = (e) => (uid) => memberName(uid, S.members, { myUid: myUid(), fallback: e && e.data && e.data.owner === uid ? e.data.ownerLabel : null });
const actx = () => ({ uid: myUid() || null, now: Date.now(), role: roleNow() });

// ---------- workspace context: role, members, SLA policy, KEV ----------
function bind(ctx) {
  S.ctx = ctx || S.ctx;
  const k = wsKey();
  if (k === S.wsk) return;
  S.wsk = k;
  S.sel.clear(); S.detailId = null; S.savedName = "";
  S.role = null; S.roleErr = ""; S.members = []; S.teamP = null;
  S.policy = normalizePolicy(SLA_DEFAULTS); S.policyLoaded = false;
  const v = lsGet(LS_VIEW + k);
  S.view = VIEWS.includes(v) ? v : "open";
  const g = lsGet(LS_GROUP + k);
  S.group = GROUPS.includes(g) ? g : "none";
  try { S.saved = normalizeSaved(JSON.parse(lsGet(LS_SAVED + (myUid() || "anon") + "__" + k) || "[]"), VIEWS); } catch (_) { S.saved = []; }
}

function loadTeam() {
  if (S.teamP) return S.teamP;
  const u = (S.ctx && S.ctx.user) || {};
  if (isPersonal()) {
    S.role = "owner";
    S.members = [{ uid: myUid(), label: u.displayName || u.email || "You", role: "owner" }];
    S.teamP = Promise.resolve();
    return S.teamP;
  }
  const wid = teamWid(), k = S.wsk;
  S.teamP = Promise.resolve().then(() => S.ctx.listMembers(wid)).then(({ members }) => {
    if (k !== S.wsk) return;
    const list = (members || []).filter((m) => m && m.uid);
    S.members = list.filter((m) => m.role !== "removed").map((m) => ({ uid: m.uid, label: m.label || "", role: m.role }));
    const me = list.find((m) => m.uid === myUid());
    S.role = me && me.role !== "removed" ? me.role : "viewer";
  }).catch((err) => {
    if (k !== S.wsk) return;
    S.role = "viewer";
    S.roleErr = "Your workspace role could not be loaded" + (err && err.message ? " (" + err.message + ")" : "") + ", so editing is off.";
  });
  return S.teamP;
}

function loadPolicy() {
  const k = S.wsk;
  return getSlaPolicy().then((p) => { if (k !== S.wsk) return; S.policy = p; S.policyLoaded = true; refresh(); }).catch(() => {});
}

function loadKev() {
  if (S.kev) return Promise.resolve(S.kev);
  if (S.kevP) return S.kevP;
  S.kevState = "loading";
  S.kevP = fetch(KEV_URL, { credentials: "same-origin" })
    .then((r) => (r.ok ? r.json() : Promise.reject(new Error("HTTP " + r.status))))
    .then((j) => {
      const set = new Set();
      for (const x of (j && j.data) || []) if (x && x.cve) set.add(String(x.cve).toUpperCase());
      if (!set.size) throw new Error("empty index");
      S.kev = set; S.kevState = "ok"; S.kevMeta = { count: set.size, updated: j.updated || "" };
      return set;
    })
    .catch(() => { S.kevState = "failed"; S.kevP = null; return null; });
  return S.kevP;
}

function refresh() { if (S.ctx && S.el && S.el.isConnected && !S.el.hidden) S.ctx.withGraph(repaintFindingsQueue); }

// Team graph changes from another member arrive as secgraph:sync in this document.
let syncBound = false;
function bindSync() {
  if (syncBound) return;
  syncBound = true;
  let t = 0;
  document.addEventListener("secgraph:sync", () => {
    clearTimeout(t);
    t = setTimeout(() => {
      if (!S.el || !S.el.isConnected || S.el.hidden || typing()) return;
      if (S.ctx && S.ctx.isActive && !S.ctx.isActive()) return;
      refresh();
    }, 350);
  });
}

// ---------- styles ----------
function injectStyle() {
  if (document.getElementById("fq-css")) return;
  const st = document.createElement("style"); st.id = "fq-css";
  st.textContent = `
.fq-tabs{display:flex;gap:2px;overflow-x:auto;overflow-y:hidden;scrollbar-width:thin;border-bottom:1px solid rgba(23,33,56,.1);margin:0 0 12px}
@media(max-width:560px){.fq-tabs{flex-wrap:wrap;overflow:visible;row-gap:0}}
.fq-tab{appearance:none;border:0;background:none;font:inherit;font-size:12.5px;font-weight:600;color:#5a6680;padding:9px 12px 10px;border-bottom:2px solid transparent;margin-bottom:-1px;cursor:pointer;white-space:nowrap;display:inline-flex;align-items:center;gap:7px}
.fq-tab:hover{color:#141c2e}
.fq-tab.on{color:var(--dk-acc,#2552c6);border-bottom-color:var(--dk-acc,#2552c6)}
.fq-tab .n{font-size:11px;font-weight:700;font-variant-numeric:tabular-nums;background:rgba(23,33,56,.07);color:#5a6680;border-radius:20px;padding:1px 7px}
.fq-tab.on .n{background:var(--dk-accbg,rgba(37,82,198,.08));color:var(--dk-acc,#2552c6)}
.fq-tab.hot .n{background:rgba(224,56,58,.12);color:#c62828}
.fq-saved{display:flex;gap:8px;align-items:center;flex:none;max-width:100%}
.dk-fnd input[type=checkbox]{min-height:0;padding:0;width:18px;height:18px;flex:none} /* the global mobile 42px input rule must not inflate checkboxes */
.fq-saved .dk-isel{min-width:0;width:auto}
.fq-saved .dk-tibtn{flex:none;white-space:nowrap}
.dk-fndt th,.dk-fndt td.ag,.dk-fndt .pill{white-space:nowrap}
.dk-fndt .fq-grp td{background:rgba(23,33,56,.045);font-weight:700;font-size:11.5px;letter-spacing:.02em;color:#2a3450;padding:7px 11px;border-top:2px solid rgba(23,33,56,.12)}
.dk-fndt .fq-grp .fq-grpn{display:inline-block;margin-left:8px;font-weight:700;font-variant-numeric:tabular-nums;background:rgba(23,33,56,.08);color:#5a6680;border-radius:20px;padding:0 8px}
.fq-note{font-size:12px;color:#5a6680;margin:-2px 0 10px;padding:7px 11px;background:rgba(23,33,56,.035);border-radius:8px;overflow-wrap:anywhere}
.fq-note.warn{background:rgba(245,146,11,.1);color:#7a4a00}
.fq-bulk .dk-isel{height:32px}
.fq-bulk b{margin-right:4px}
.fq-due{display:inline-block;font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 9px;white-space:nowrap;border:1px solid transparent}
.fq-due.overdue{color:#c62828;background:rgba(224,56,58,.1);border-color:rgba(224,56,58,.35)}
.fq-due.soon{color:#9a5a00;background:rgba(245,146,11,.13);border-color:rgba(245,146,11,.4)}
.fq-due.track{color:#44506a;background:rgba(23,33,56,.05);border-color:rgba(23,33,56,.12)}
.fq-due.exc{color:#6d3fc0;background:rgba(155,92,240,.1);border-color:rgba(155,92,240,.35)}
.fq-due.none{color:#8a93a6;padding:1px 2px}
.fq-chip{display:inline-block;margin-left:6px;font-size:10px;font-weight:700;letter-spacing:.03em;border-radius:20px;padding:1px 7px;vertical-align:1px;white-space:nowrap}
.fq-chip.reg{color:#c62828;background:rgba(224,56,58,.1)}
.fq-chip.kev{color:#fff;background:#b3261e}
.fq-chip.ok{color:#0f7a45;background:rgba(18,168,95,.12)}
.fq-chip.vuln{color:#5a6680;background:rgba(23,33,56,.07)}
.dk-itable td.fq-nm{min-width:220px;max-width:460px}
.fq-open{appearance:none;border:0;background:none;padding:0;font:inherit;font-weight:600;color:#141c2e;text-align:left;cursor:pointer;overflow-wrap:anywhere}
.fq-open:hover{color:var(--dk-acc,#2552c6);text-decoration:underline}
.fq-own{white-space:nowrap;max-width:180px;overflow:hidden;text-overflow:ellipsis}
.fq-own.un{color:#8a93a6}
.fq-res{display:block;font-size:11px;color:#687388;margin-top:2px;white-space:nowrap}
.dk-kpi.fq-click{cursor:pointer!important}
/* detail */
.fq-dtop{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:0 0 14px}
.fq-crumb{font-size:12.5px;color:#687388;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.fq-dpills{display:flex;align-items:center;gap:8px;flex-wrap:wrap;margin-bottom:10px}
.fq-dpills .fq-chip{margin-left:0}
.fq-dtitle{font-size:22px;line-height:1.3;font-weight:700;margin:0 0 6px;overflow-wrap:anywhere;color:#141c2e}
.fq-dmeta{font-size:12.5px;color:#687388;margin-bottom:14px;overflow-wrap:anywhere}
.fq-dctl{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}
.fq-fld{display:flex;flex-direction:column;gap:6px;min-width:0}
.fq-fld>.l{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:#6a7488;font-weight:700}
.fq-fld .dk-isel{max-width:none;width:100%}
.fq-fld .h{font-size:11.5px;color:#687388;line-height:1.45;overflow-wrap:anywhere}
.fq-row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.fq-row .dk-tibtn{height:32px;padding:0 11px}
.fq-dgrid{display:grid;grid-template-columns:minmax(0,2fr) minmax(0,1fr);gap:18px;align-items:start}
.fq-dgrid .dk-ovp{margin-bottom:18px}
@media(max-width:1000px){.fq-dgrid{grid-template-columns:minmax(0,1fr)}}
.fq-sec{margin:0 0 14px}
.fq-sec:last-child{margin-bottom:0}
.fq-sec>.hd{font-size:10.5px;letter-spacing:.05em;text-transform:uppercase;color:#6a7488;font-weight:700;margin-bottom:6px}
.fq-txt{font-size:13px;line-height:1.6;color:#2b3448;white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.fq-mut{font-size:12.5px;color:#8a93a6}
.fq-pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;line-height:1.55;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.08);border-radius:8px;padding:10px 12px;margin:0;max-height:460px;overflow:auto;color:#1a2233}
.fq-pb{margin:0;padding-left:20px;font-size:13px;line-height:1.6;color:#2b3448}
.fq-pb li{margin:0 0 5px}
.fq-pbverify{margin-top:9px;font-size:12.5px;color:#2b3448;background:rgba(18,168,95,.07);border:1px solid rgba(18,168,95,.2);border-radius:8px;padding:8px 11px}
.fq-pbref{display:flex;flex-wrap:wrap;gap:6px;margin-top:9px}
.fq-pbref span{font-size:11px;color:#5a6680;background:rgba(23,33,56,.05);border-radius:5px;padding:2px 7px}
.fq-ctl{display:flex;flex-wrap:wrap;gap:6px}
.fq-ctl span{font-size:11.5px;font-weight:600;color:#38435c;background:rgba(23,33,56,.05);border:1px solid rgba(23,33,56,.1);border-radius:6px;padding:2px 8px;overflow-wrap:anywhere}
.fq-kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:4px 12px;font-size:12.5px;margin:0 0 10px}
.fq-kv dt{color:#687388}
.fq-kv dd{margin:0;color:#1a2233;overflow-wrap:anywhere;white-space:pre-wrap}
.fq-hist{list-style:none;margin:10px 0 0;padding:0;font-size:12px;color:#44506a}
.fq-hist li{padding:7px 0;border-top:1px solid rgba(23,33,56,.07);overflow-wrap:anywhere}
.fq-tk{list-style:none;margin:0 0 10px;padding:0}
.fq-tk li{padding:6px 0;border-bottom:1px solid rgba(23,33,56,.07);font-size:12.5px;overflow-wrap:anywhere}
.fq-tk a{color:var(--dk-acc,#2552c6);font-weight:600}
.fq-tl{list-style:none;margin:0 0 14px;padding:0}
.fq-tl li{position:relative;padding:0 0 12px 18px;font-size:12.5px;color:#2b3448;overflow-wrap:anywhere}
.fq-tl li:before{content:"";position:absolute;left:3px;top:6px;width:7px;height:7px;border-radius:50%;background:#9aa4ba}
.fq-tl li:after{content:"";position:absolute;left:6px;top:15px;bottom:0;width:1px;background:rgba(23,33,56,.12)}
.fq-tl li:last-child:after{display:none}
.fq-tl li.c:before{background:var(--dk-acc,#2552c6)}
.fq-tl .w{display:block;font-size:11px;color:#8a93a6;margin-top:1px}
.fq-tl .cm{margin-top:6px;padding:8px 11px;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.08);border-radius:8px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55}
.fq-cbox textarea{width:100%;box-sizing:border-box;min-height:84px;resize:vertical;font:inherit;font-size:13px;color:#1a2233;background:#fff;border:1px solid rgba(23,33,56,.16);border-radius:8px;padding:9px 11px;outline:none}
.fq-cbox textarea:focus{border-color:var(--dk-acc,#2552c6)}
.fq-cbox .fq-row{justify-content:space-between;margin-top:6px}
.fq-cnt{font-size:11.5px;color:#8a93a6;font-variant-numeric:tabular-nums}
/* SLA settings */
.fq-sla .dk-setrow input{width:96px}
.fq-sla .dk-setrow .u{font-size:12.5px;color:#687388;flex:none}
.fq-sla .fq-slad{font-size:12.5px;color:#5a6680;line-height:1.55;margin:0 0 6px}
.fq-slamsg{font-size:12.5px;min-height:1em;margin:10px 0 0;overflow-wrap:anywhere}
.fq-slamsg.err{color:#b00020}.fq-slamsg.ok{color:#0f7a45}
@media(max-width:520px){.fq-sla .dk-setrow{flex-wrap:wrap}.fq-sla .dk-setrow .m{flex:1 1 100%}}
/* form dialog (reuses the shared .dn-modal shell) */
.fqm .fqm-fld{display:flex;flex-direction:column;gap:5px;margin-bottom:10px}
.fqm .fqm-lbl{font-size:.78rem;font-weight:600;color:var(--txt,#0f172a)}
.fqm .fqm-help{font-size:.74rem;color:var(--mut,#64748b);line-height:1.45;overflow-wrap:anywhere}
.fqm select.dn-modal-in{appearance:auto}
.fqm .fqm-err{color:#b00020;font-size:.8rem;min-height:1em;margin-top:2px;overflow-wrap:anywhere}
`;
  document.head.appendChild(st);
}

// ---------- form dialog ----------
// fields: [{ key, label, type: "text"|"textarea"|"date"|"select", options:[[value,label]], required,
//   help, placeholder, min, max, maxlength, value, list:[labels] }]. onSubmit(values) returns an
// error string (kept open, shown inline) or nothing (closes). Resolves true when submitted.
function formModal({ title, desc, fields = [], submitText = "Save", danger = false, onSubmit }) {
  injectStyle();
  return new Promise((resolve) => {
    const prevFocus = document.activeElement;
    const ov = document.createElement("div");
    ov.className = "dn-modal-ov";
    const fid = "fqm" + Math.random().toString(36).slice(2, 8);
    ov.innerHTML = `<div class="dn-modal fqm" role="dialog" aria-modal="true" aria-label="${E(title)}">
      <div class="dn-modal-h">${E(title)}</div>
      ${desc ? `<p class="dn-modal-d">${E(desc)}</p>` : ""}
      <div class="dn-modal-body">${fields.map((f) => {
        const id = fid + "-" + f.key;
        const req = f.required ? " required" : "";
        let ctl;
        if (f.type === "select") ctl = `<select class="dn-modal-in" id="${id}" data-k="${E(f.key)}">${(f.options || []).map(([v, l]) => `<option value="${E(v)}"${String(v) === String(f.value ?? "") ? " selected" : ""}>${E(l)}</option>`).join("")}</select>`;
        else if (f.type === "textarea") ctl = `<textarea class="dn-modal-ta" id="${id}" data-k="${E(f.key)}" rows="${f.rows || 3}"${f.maxlength ? ` maxlength="${f.maxlength}"` : ""} placeholder="${E(f.placeholder || "")}"${req}>${E(f.value || "")}</textarea>`;
        else ctl = `<input class="dn-modal-in" id="${id}" data-k="${E(f.key)}" type="${f.type === "date" ? "date" : "text"}" placeholder="${E(f.placeholder || "")}" value="${E(f.value || "")}"${f.min ? ` min="${E(f.min)}"` : ""}${f.max ? ` max="${E(f.max)}"` : ""}${f.maxlength ? ` maxlength="${f.maxlength}"` : ""}${f.list ? ` list="${id}-dl"` : ""} autocomplete="off"${req}>${f.list ? `<datalist id="${id}-dl">${f.list.map((x) => `<option value="${E(x)}"></option>`).join("")}</datalist>` : ""}`;
        return `<div class="fqm-fld"><label class="fqm-lbl" for="${id}">${E(f.label)}${f.required ? "" : " (optional)"}</label>${ctl}${f.help ? `<span class="fqm-help">${E(f.help)}</span>` : ""}</div>`;
      }).join("")}<div class="fqm-err" role="alert"></div></div>
      <div class="dn-modal-actions"><div class="dn-modal-extra"></div><div class="dn-modal-main">
        <button type="button" class="btn ghost sm" data-cancel>Cancel</button>
        <button type="button" class="btn sm${danger ? " dn-modal-danger" : ""}" data-ok>${E(submitText)}</button>
      </div></div></div>`;
    document.body.appendChild(ov);
    requestAnimationFrame(() => ov.classList.add("open"));
    const errEl = ov.querySelector(".fqm-err");
    const vals = () => { const o = {}; ov.querySelectorAll("[data-k]").forEach((x) => { o[x.dataset.k] = x.value; }); return o; };
    let busy = false;
    const close = (r) => {
      ov.classList.remove("open"); document.removeEventListener("keydown", onKey);
      setTimeout(() => ov.remove(), 150);
      if (prevFocus && typeof prevFocus.focus === "function" && document.contains(prevFocus)) { try { prevFocus.focus(); } catch (_) {} }
      resolve(r);
    };
    const submit = async () => {
      if (busy) return;
      const v = vals();
      const miss = fields.find((f) => f.required && !String(v[f.key] || "").trim());
      if (miss) { errEl.textContent = `${miss.label} is required.`; const x = ov.querySelector(`[data-k="${miss.key}"]`); if (x) x.focus(); return; }
      busy = true;
      let err = null;
      try { err = onSubmit ? await onSubmit(v) : null; } catch (x) { err = (x && x.message) || String(x); }
      busy = false;
      if (err) { errEl.textContent = err; return; }
      close(true);
    };
    ov.querySelector("[data-ok]").onclick = submit;
    ov.querySelector("[data-cancel]").onclick = () => close(false);
    ov.addEventListener("mousedown", (e) => { if (e.target === ov) close(false); });
    const onKey = (e) => {
      const all = document.querySelectorAll(".dn-modal-ov");
      if (all.length && all[all.length - 1] !== ov) return;
      if (e.key === "Escape") { e.preventDefault(); close(false); }
      else if (e.key === "Enter" && e.target && e.target.tagName !== "TEXTAREA" && e.target.tagName !== "BUTTON") { e.preventDefault(); submit(); }
      else if (e.key === "Tab") {
        const f = [...ov.querySelectorAll("button, input, textarea, select")].filter((x) => !x.disabled && x.offsetParent !== null);
        if (!f.length) return;
        if (e.shiftKey && document.activeElement === f[0]) { e.preventDefault(); f[f.length - 1].focus(); }
        else if (!e.shiftKey && document.activeElement === f[f.length - 1]) { e.preventDefault(); f[0].focus(); }
      }
    };
    document.addEventListener("keydown", onKey);
    const first = ov.querySelector("[data-k]") || ov.querySelector("[data-ok]");
    if (first) first.focus();
  });
}

// ---------- applying changes ----------
// Apply one change to many findings (applyBulk + one batched write). Returns the summary.
function applyTo(m, ids, change) {
  const ents = ids.map((id) => m.getEntity(id)).filter(Boolean);
  const res = applyBulk(ents, change, actx());
  m.batch(() => { for (const r of res) if (!r.error && !r.noop && r.updates) m.updateEntity(r.id, r.updates); });
  const sum = summarizeBulk(res);
  sum.failedIds = res.filter((r) => r.error).map((r) => r.id);
  sum.firstError = (res.find((r) => r.error) || {}).error || "";
  return sum;
}
// A form-driven change: validate against every target first so a shared validation
// error (missing reason, bad date) stays in the dialog instead of skipping every item.
function preflight(m, ids, change) {
  const ents = ids.map((id) => m.getEntity(id)).filter(Boolean);
  if (!ents.length) return "These findings are no longer in the security graph.";
  const res = applyBulk(ents, change, actx());
  return res.every((r) => r.error) && new Set(res.map((r) => r.error)).size === 1 ? res[0].error : null;
}
function withM(fn) { S.ctx.withGraph((m) => { if (!m || !m.getEntity || !m.updateEntity) { toast("The security graph is still loading. Try again in a moment."); return; } fn(m); }); }

function afterBulk(sum, ids, okText) {
  const fromSel = ids.length === S.sel.size && ids.every((id) => S.sel.has(id));
  toast(okText && ids.length === 1 && sum.updated === 1 ? okText : sum.text);
  if (fromSel) { S.sel.clear(); for (const id of sum.failedIds || []) S.sel.add(id); } // keep the skipped ones selected to fix
  refresh();
}

// Run a change through a form dialog. build(values) -> change | error string.
function formChange(ids, dialog, build, okText) {
  withM((m) => {
    formModal({
      ...dialog,
      onSubmit: (v) => {
        const change = build(v);
        if (typeof change === "string") return change;
        const err = preflight(m, ids, change);
        if (err) return err;
        afterBulk(applyTo(m, ids, change), ids, okText);
        return null;
      },
    });
  });
}

function memberOptions() {
  const me = myUid();
  const list = S.members.filter((x) => x.uid !== me).sort((a, b) => String(a.label || a.uid).localeCompare(String(b.label || b.uid)));
  return list.map((x) => [x.uid, x.label || x.uid.slice(0, 8) + "..."]);
}
function assignChange(val) {
  if (val === "__none") return { op: "assign", owner: null };
  const uid = val === "__me" ? myUid() : val;
  if (!uid) return null;
  const mem = S.members.find((x) => x.uid === uid);
  const u = (S.ctx && S.ctx.user) || {};
  const label = (mem && mem.label) || (uid === myUid() ? u.displayName || u.email || "" : "");
  return { op: "assign", owner: uid, ownerLabel: label };
}
const assignSelect = (id, cur, lead) => `<select class="dk-isel" ${id} aria-label="Owner">${lead ? `<option value="">${E(lead)}</option>` : ""}<option value="__me"${cur && cur === myUid() ? " selected" : ""}>Me</option><option value="__none"${lead ? "" : !cur ? " selected" : ""}>Unassigned</option>${memberOptions().map(([v, l]) => `<option value="${E(v)}"${v === cur ? " selected" : ""}>${E(l)}</option>`).join("")}${cur && cur !== myUid() && !S.members.some((x) => x.uid === cur) ? `<option value="${E(cur)}" selected>${E(memberName(cur, S.members, {}))}</option>` : ""}</select>`;

function statusFlow(ids, to) {
  if (to !== "resolved" && to !== "closed") {
    withM((m) => afterBulk(applyTo(m, ids, { op: "status", status: to }), ids));
    return;
  }
  formChange(ids, {
    title: (to === "resolved" ? "Resolve " : "Close ") + (ids.length === 1 ? "finding" : ids.length + " findings"),
    desc: "Record why. Risk accepted needs an active risk exception with an expiry on each finding.",
    submitText: to === "resolved" ? "Resolve" : "Close",
    fields: [{ key: "resolution", label: "Resolution", type: "select", required: true, options: [["", "Choose a resolution"], ...RESOLUTIONS.map((r) => [r, RESOLUTION_LABEL[r] || r])] }],
  }, (v) => ({ op: "status", status: to, resolution: v.resolution }), "Status set to " + to);
}

function dueFlow(ids, e) {
  const now = Date.now();
  const d = e && e.data && Number.isFinite(toMs(e.data.dueAt)) ? localDay(toMs(e.data.dueAt)) : "";
  formChange(ids, {
    title: "Set due date" + (ids.length > 1 ? ` for ${ids.length} findings` : ""),
    desc: "Overrides the SLA due date. The reason is kept in the finding's history.",
    submitText: "Set due date",
    fields: [
      { key: "date", label: "Due date", type: "date", required: true, value: d, min: localDay(now) },
      { key: "reason", label: "Reason", type: "textarea", required: true, maxlength: 500, placeholder: "Why this date" },
    ],
  }, (v) => { const at = dateInputToMs(v.date); return at == null ? "Pick a valid due date." : { op: "due", dueAt: at, reason: v.reason }; }, "Due date set");
}

// The Risk Register (riskreg) tool mirrors every risk into the graph as a FINDING
// entity it owns (source "riskreg"). An exception links to one of those real entries
// instead of a free-text id, so "accept this risk" points at a tracked risk.
function riskRegisterRisks() {
  let out = [];
  try { S.ctx.withGraph((m) => { if (m && m.listEntities) out = (m.listEntities({ type: "FINDING" }) || []).filter((r) => r.source === "riskreg").map((r) => ({ id: r.id, name: String(r.name || "Untitled risk").slice(0, 90) })).sort((a, b) => a.name.localeCompare(b.name)); }); } catch (_) {}
  return out;
}
const RISK_OTHER = "__other__";

function exceptionFlow(ids, e) {
  const now = Date.now();
  const x = e && e.data && e.data.exception;
  const curRisk = x && x.riskId ? String(x.riskId) : "";
  const risks = riskRegisterRisks();
  const linked = risks.some((r) => r.id === curRisk);
  const riskFields = risks.length
    ? [
        { key: "riskSel", label: "Risk register entry", type: "select",
          value: linked ? curRisk : (curRisk ? RISK_OTHER : ""),
          options: [["", "— not linked —"], ...risks.map((r) => [r.id, r.name]), [RISK_OTHER, "Other / external id"]],
          help: "Link this accepted risk to an entry in the Risk Register tool." },
        { key: "riskId", label: "External risk id", type: "text", maxlength: 120, value: linked ? "" : curRisk, placeholder: "GRC / external id",
          help: 'Only for a risk tracked outside this platform (choose "Other" above).' },
      ]
    : [
        { key: "riskId", label: "Risk register id", type: "text", maxlength: 120, value: curRisk, placeholder: "Risk id",
          help: "No risks in the Risk Register tool yet — add risks there to link them here, or enter an external id." },
      ];
  formChange(ids, {
    title: (x ? "Replace risk exception" : "Add risk exception") + (ids.length > 1 ? ` for ${ids.length} findings` : ""),
    desc: `A time-boxed, approved decision to carry this risk. It must expire within ${EXCEPTION_MAX_DAYS} days; on expiry the finding returns to the queue.`,
    submitText: x ? "Replace exception" : "Add exception",
    fields: [
      { key: "reason", label: "Reason", type: "textarea", required: true, maxlength: 500, placeholder: "Why the risk is accepted", help: "Note any compensating control." },
      { key: "approver", label: "Approved by", type: "text", required: true, maxlength: 120, placeholder: "Name or role", list: S.members.map((mm) => mm.label).filter(Boolean), help: "Pick a member or type a name or role." },
      { key: "expires", label: "Expires on", type: "date", required: true, min: localDay(now), max: exceptionMaxDay(now) },
      ...riskFields,
    ],
  }, (v) => {
    const n = Date.now(), maxDay = exceptionMaxDay(n);
    if (String(v.expires) > maxDay) return `An exception can last at most ${EXCEPTION_MAX_DAYS} days: pick ${fmtDay(dateInputToMs(maxDay))} or earlier.`;
    // Clamp only the end-of-day overshoot on the last allowed day itself.
    const exp = dateInputToMs(v.expires, { maxMs: n + EXCEPTION_MAX_DAYS * DAY_MS });
    if (exp == null) return "Pick a valid expiry date.";
    // A chosen register entry wins; "Other" (or no register entries) uses the free-text id.
    let riskId = "";
    if (risks.length) { const sel = String(v.riskSel || ""); riskId = sel && sel !== RISK_OTHER ? sel : String(v.riskId || "").trim(); } // an id typed without picking "Other" is kept, not dropped
    else riskId = String(v.riskId || "").trim();
    return { op: "exception", reason: v.reason, approver: v.approver, expiresAt: exp, riskId };
  }, x ? "Risk exception replaced" : "Risk exception added");
}

function ticketsFlow(ids) {
  withM((m) => {
    const ents = ids.map((id) => m.getEntity(id)).filter(Boolean);
    if (!ents.length) { toast("No findings selected"); return; }
    openTicketExport(ents, {
      onLinked: (id, t) => new Promise((resolve, reject) => {
        S.ctx.withGraph((g) => {
          const cur = g && g.getEntity ? g.getEntity(id) : null;
          if (!cur) { reject(new Error("Finding no longer in the graph")); return; }
          const r = applyChange(cur, { op: "ticket", url: t.url, label: t.label }, actx());
          if (r.error) { reject(new Error(r.error)); return; }
          if (!r.noop) g.updateEntity(id, r.updates);
          resolve();
        });
      }),
    }).then(refresh);
  });
}

// ---------- the queue ----------
export function mountFindingsQueue(el, ctx) {
  injectStyle(); bindSync(); bind(ctx);
  S.el = el;
  S.detailId = null;
  const IC = ctx.IC || {};
  el.innerHTML = `<div class="fq-q">
      <div class="dk-ovhead"><div><h1>Findings</h1><p>Every finding and vulnerability your tools have recorded, as one work queue: owners, SLA due dates, risk exceptions and tickets. Sample data is excluded unless you include it.</p></div>
        <div class="when"><button class="dk-tibtn" id="dkFndCsv">${IC.copy || ""} Export CSV</button> <button class="dk-tibtn" id="dkFndJson">${IC.copy || ""} Export JSON</button></div></div>
      <div class="dk-kpis" id="dkFndKpis"></div>
      <div class="dk-ovp">
        <h2 data-explain="panel.findings">${IC.alert || ""} Finding queue <span class="mo" data-tool="secgraph">Open graph</span></h2>
        <div class="fq-tabs" id="fqTabs" role="tablist" aria-label="Queue views"></div>
        <div class="dk-invbar">
          <div class="dk-isearch">${ctx.IC_SEARCH || ""}<input id="dkFndQ" aria-label="Search findings" placeholder="Search findings" value="${E(S.f.q)}" autocomplete="off" spellcheck="false"></div>
          <select id="dkFndSev" class="dk-isel" aria-label="Severity"></select>
          <select id="dkFndStatus" class="dk-isel" aria-label="Status"></select>
          <select id="dkFndSrc" class="dk-isel" aria-label="Source"></select>
          <label class="dk-invsim" data-explain="inv.sim"><input type="checkbox" id="dkFndSim"${S.f.sim ? " checked" : ""}> Include simulated / sample</label>
          <select id="dkFndGroup" class="dk-isel" aria-label="Group by">${GROUPS.map((g) => `<option value="${g}"${g === S.group ? " selected" : ""}>${E(g === "none" ? "No grouping" : "Group: " + GROUP_LABEL[g])}</option>`).join("")}</select>
          <div class="fq-saved"><select id="fqSaved" class="dk-isel" aria-label="Saved views"></select><button class="dk-tibtn" id="fqSave" style="height:38px">Save view</button><button class="dk-tibtn" id="fqDel" style="height:38px" hidden>Delete view</button></div>
        </div>
        <div id="fqNotes"></div>
        <div class="dk-fndbulk fq-bulk" id="dkFndBulk" hidden></div>
        <div id="dkFndTable"><div class="dk-loading"><span class="sp"></span>Reading the security graph...</div></div>
      </div></div>
    <div class="fq-d" hidden></div>`;
  const $ = (s) => el.querySelector(s);
  const q = $("#dkFndQ"); let qT = 0;
  const changed = () => { S.savedName = ""; refresh(); };
  q.oninput = () => { clearTimeout(qT); qT = setTimeout(() => { S.f.q = q.value; changed(); }, 150); };
  $("#dkFndSev").onchange = (e) => { S.f.severity = e.target.value; changed(); };
  $("#dkFndStatus").onchange = (e) => { S.f.status = e.target.value; changed(); };
  $("#dkFndSrc").onchange = (e) => { S.f.source = e.target.value; changed(); };
  $("#dkFndSim").onchange = (e) => { S.f.sim = e.target.checked; changed(); };
  $("#dkFndGroup").onchange = (e) => { S.group = GROUPS.includes(e.target.value) ? e.target.value : "none"; lsSet(LS_GROUP + S.wsk, S.group); refresh(); };
  const stamp = new Date().toISOString().slice(0, 10);
  const exportRows = () => S.rows.map((r) => ({ severity: r.severity, name: r.name, type: r.type, status: r.status, resolution: r.resolution || "", owner: r.ownerName, due: r.sla.dueAt ? localDay(r.sla.dueAt) : "", sla: r.sla.state, source: r.source, createdAt: r.createdAt, updatedAt: r.updatedAt, id: r.id, tags: r.tags, sim: r.sim }));
  $("#dkFndCsv").onclick = () => { if (!S.rows.length) return toast("No findings to export"); ctx.dl("darknode-findings-" + stamp + ".csv", ctx.findings.toCSV(exportRows(), ["severity", "name", "type", "status", "resolution", "owner", "due", "sla", "source", "createdAt", "updatedAt", "id"]), "text/csv"); };
  $("#dkFndJson").onclick = () => { if (!S.rows.length) return toast("No findings to export"); ctx.dl("darknode-findings-" + stamp + ".json", JSON.stringify(exportRows(), null, 2), "application/json"); };
  $("#fqSaved").onchange = (e) => { const v = S.saved.find((x) => x.name === e.target.value); if (v) applySaved(v); };
  $("#fqSave").onclick = saveView;
  $("#fqDel").onclick = deleteView;
  $("#fqTabs").onclick = (e) => { const b = e.target.closest("[data-view]"); if (b) setView(b.dataset.view); };
  $("#dkFndKpis").onclick = (e) => { const k = e.target.closest("[data-view]"); if (k) setView(k.dataset.view); };
  S.teamP = null;           // re-read members and my role on every visit
  loadTeam().then(refresh);
  loadKev().then(refresh);
  loadPolicy();
  refresh();
}

function setView(v) {
  if (!VIEWS.includes(v)) return;
  S.view = v; S.savedName = "";
  lsSet(LS_VIEW + S.wsk, v);
  refresh();
}

const savedKey = () => LS_SAVED + (myUid() || "anon") + "__" + S.wsk;
function storeSaved() { lsSet(savedKey(), JSON.stringify(S.saved)); }
async function saveView() {
  const name = typeof window.dnPrompt === "function" ? await window.dnPrompt("Save view", { desc: `Saves the ${VIEW_LABEL[S.view]} view with the current search and filters, for you in this workspace.`, placeholder: "View name", value: S.savedName || "", submitText: "Save" }) : null;
  const n = String(name || "").trim().slice(0, 60);
  if (!n) return;
  S.saved = upsertSaved(S.saved, { name: n, view: S.view, f: { ...S.f }, ts: Date.now() }, VIEWS);
  S.savedName = n; storeSaved(); toast(`Saved view "${n}"`); refresh();
}
async function deleteView() {
  const n = S.savedName; if (!n) return;
  const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm(`Delete saved view "${n}"?`, "Only the saved shortcut is removed. Findings are not changed.", { submitText: "Delete", danger: true }) : false;
  if (!ok) return;
  S.saved = removeSaved(S.saved, n, VIEWS); S.savedName = ""; storeSaved(); toast("Saved view deleted"); refresh();
}
function applySaved(v) {
  S.view = v.view; S.f = { ...S.f, ...v.f }; S.savedName = v.name;
  lsSet(LS_VIEW + S.wsk, S.view);
  const q = S.el.querySelector("#dkFndQ"); if (q) q.value = S.f.q;
  const sim = S.el.querySelector("#dkFndSim"); if (sim) sim.checked = !!S.f.sim;
  refresh();
}

// Bucket queue rows by one unambiguous dimension. Returns ordered groups
// [{ key, label, rows }]: severity in severity order, everything else by size
// then label. Pure (no DOM) so it can be unit-tested.
export function groupRows(rows, by) {
  const keyer = {
    source: (r) => [String(r.source || ""), String(r.source || "Unknown source")],
    severity: (r) => { const s = String(r.severity || "none").toLowerCase(); return [s, SEV_LABEL[s] || "Unrated"]; },
    owner: (r) => [String(r.owner || ""), String(r.ownerShow || "Unassigned")],
    status: (r) => { const s = String(r.status || "new").toLowerCase(); return [s, cap(s)]; },
  }[by];
  if (!keyer) return [{ key: "", label: "", rows: rows.slice() }];
  const map = new Map();
  for (const r of rows) { const [k, label] = keyer(r); if (!map.has(k)) map.set(k, { key: k, label, rows: [] }); map.get(k).rows.push(r); }
  const groups = [...map.values()];
  if (by === "severity") { const ord = ["critical", "high", "medium", "low", "info", "none"]; groups.sort((a, b) => (ord.indexOf(a.key) + 1 || 99) - (ord.indexOf(b.key) + 1 || 99)); }
  else groups.sort((a, b) => b.rows.length - a.rows.length || String(a.label).localeCompare(String(b.label)));
  return groups;
}

/** Repaint the scene (queue or open detail) from the graph module `m`. */
export function repaintFindingsQueue(m) {
  if (!S.el || !S.el.isConnected || !S.ctx) return;
  if (S.detailId) paintDetail(m); else paintQueue(m);
}

function paintQueue(m) {
  const el = S.el, ctx = S.ctx, box = el.querySelector("#dkFndTable"); if (!box) return;
  const now = Date.now(), vo = viewOpts(now);
  const ents = m && m.listEntities ? m.listEntities({ type: ["FINDING", "VULNERABILITY"] }) : [];
  const byId = new Map(ents.map((e) => [e.id, e]));
  const all = ctx.findings.collectFindings(ents, { includeSim: S.f.sim });
  for (const r of all) {
    const e = byId.get(r.id), d = (e && e.data) || {};
    r.e = e; r.sla = slaOf(e, now); r.title = cleanTitle(e); r.resolution = d.resolution || null;
    r.owner = d.owner || null; r.ownerName = r.owner ? memberName(r.owner, S.members, { fallback: d.ownerLabel }) : "Unassigned";
    r.ownerShow = r.owner ? memberName(r.owner, S.members, { myUid: myUid(), fallback: d.ownerLabel }) : "Unassigned";
    r.regressed = !!d.regressed && isOpenStatus(r.status); r.kev = isKnownExploited(e, S.kev || undefined);
  }
  const real = all.filter((r) => !r.sim);
  const c = ctx.findings.findingCounts(real);
  const overdue = real.filter((r) => r.sla.state === "overdue").length, dueWeek = real.filter((r) => r.sla.state === "due_soon").length;
  el.querySelector("#dkFndKpis").innerHTML = [[c.critical, "Open critical", sevC("critical"), "fnd.critical"], [c.high, "Open high", sevC("high"), "fnd.high"], [overdue, "Overdue", "#c62828", "", "overdue"], [dueWeek, "Due this week", "#d98200", "", "due_week"], [c.open, "Open findings", "#4f86ff", "fnd.open", "open"], [c.resolved, "Resolved or closed", "#12a85f", "fnd.resolved"]]
    .map(([v, l, a, x, view]) => `<div class="dk-kpi${view ? " fq-click" : ""}"${x ? ` data-explain="${x}"` : ""}${view ? ` data-view="${view}" role="button" tabindex="0" title="Show ${E(VIEW_LABEL[view])}"` : ""} style="--a:${a};cursor:default"><div class="kn">${v.toLocaleString()}</div><div class="kl">${E(l)}</div></div>`).join("");
  const opt = (v, l, cur) => `<option value="${E(v)}"${v === cur ? " selected" : ""}>${E(l)}</option>`;
  el.querySelector("#dkFndSev").innerHTML = opt("", "All severities", S.f.severity) + SEVERITY_LEVELS.map((s) => opt(s, cap(s), S.f.severity)).join("");
  el.querySelector("#dkFndStatus").innerHTML = opt("", "Any status", S.f.status) + opt("open", "Open", S.f.status) + ["new", "investigating", "resolved", "closed"].map((s) => opt(s, cap(s), S.f.status)).join("");
  const srcs = [...new Set(all.map((r) => r.source))].sort();
  if (S.f.source && !srcs.includes(S.f.source)) S.f.source = "";
  el.querySelector("#dkFndSrc").innerHTML = opt("", "All sources", S.f.source) + srcs.map((s) => opt(s, s, S.f.source)).join("");
  el.querySelector("#fqSaved").innerHTML = `<option value="">${S.saved.length ? "Saved views (" + S.saved.length + ")" : "No saved views"}</option>` + S.saved.map((v) => opt(v.name, v.name, S.savedName)).join("");
  el.querySelector("#fqDel").hidden = !S.savedName;

  const base = ctx.findings.filterFindings(all, S.f);
  const counts = {}; for (const v of VIEWS) counts[v] = base.filter((r) => inView(r.e, v, vo)).length;
  el.querySelector("#fqTabs").innerHTML = VIEWS.map((v) => `<button class="fq-tab${v === S.view ? " on" : ""}${v === "overdue" && counts[v] ? " hot" : ""}" role="tab" aria-selected="${v === S.view}" data-view="${v}">${E(VIEW_LABEL[v])}<span class="n">${counts[v].toLocaleString()}</span></button>`).join("");
  let rows = base.filter((r) => inView(r.e, S.view, vo));
  if (S.view === "overdue" || S.view === "due_week") rows = urgencySort(rows, (r) => r.sla);
  S.rows = rows;
  for (const id of [...S.sel]) if (!rows.some((r) => r.id === id)) S.sel.delete(id);

  const write = canWrite();
  const notes = [];
  if (!isPersonal() && S.role == null && !S.roleErr) notes.push(`<div class="fq-note">Checking your role in this workspace...</div>`);
  else if (!write) notes.push(`<div class="fq-note">${E(S.roleErr || "Read-only: viewers can't change findings.")}</div>`);
  if (S.f.sim && S.view !== "all" && all.some((r) => r.sim)) notes.push(`<div class="fq-note">Sample findings appear only in the All view; queue views hold real work.</div>`);
  if (S.kevState === "failed") notes.push(`<div class="fq-note warn">KEV matching is unavailable: the CISA KEV index could not be loaded, so CVE-based KEV due dates are not applied.</div>`);
  el.querySelector("#fqNotes").innerHTML = notes.join("");
  paintBulk();

  if (!all.length) {
    box.innerHTML = ctx.onboardHtml || `<div class="dk-nempty">No findings recorded yet.</div>`;
    box.querySelectorAll(".dk-qacard[data-tool]").forEach((b) => b.onclick = () => ctx.openTool(b.dataset.tool));
    return;
  }
  if (!rows.length) { box.innerHTML = `<div class="dk-nempty">${base.length ? `Nothing in ${E(VIEW_LABEL[S.view])} with these filters.` : "No findings match these filters."}</div>`; return; }
  const shown = rows.slice(0, 500);
  const fmt = (ms) => fmtDay(ms);
  const ncol = write ? 9 : 8;
  const rowHtml = (r) => {
    const chip = dueChip(r.sla, now, fmt);
    return `<tr data-eid="${E(r.id)}" class="fq-sev-${E(String(r.severity || "none").toLowerCase())}">${write ? `<td class="ck"><input type="checkbox" data-sel="${E(r.id)}"${S.sel.has(r.id) ? " checked" : ""} aria-label="Select finding"></td>` : ""}<td>${r.severity ? pill(sevC(r.severity), cap(r.severity)) : "-"}</td><td class="fq-nm"><button class="fq-open" data-open="${E(r.id)}">${E(r.title || r.name || "Untitled finding")}</button>${r.type === "VULNERABILITY" ? '<span class="fq-chip vuln">Vulnerability</span>' : ""}${r.kev ? '<span class="fq-chip kev" title="On the CISA Known Exploited Vulnerabilities catalog">KEV</span>' : ""}${r.regressed ? '<span class="fq-chip reg" title="Was verified fixed, then seen again">Regressed</span>' : ""}${r.sim ? ' <span class="dk-simchip">Sample</span>' : ""}</td><td><div class="fq-own${r.owner ? "" : " un"}" title="${E(r.ownerShow)}">${E(r.ownerShow)}</div></td><td><span class="fq-due ${chip.cls}"${r.sla.dueAt ? ` title="Due ${E(fmtDay(r.sla.dueAt))}"` : ""}>${E(chip.text)}</span></td><td>${pill(stC(r.status), cap(r.status))}${r.resolution ? `<span class="fq-res">${E(RESOLUTION_LABEL[r.resolution] || r.resolution)}</span>` : ""}</td><td>${E(r.source)}</td><td class="ag">${ctx.agoISO(r.createdAt)}</td><td class="ag">${ctx.agoISO(r.updatedAt)}</td></tr>`;
  };
  const body = S.group === "none"
    ? shown.map(rowHtml).join("")
    : groupRows(shown, S.group).map((g) => `<tr class="fq-grp"><td colspan="${ncol}">${E(g.label || "—")}<span class="fq-grpn">${g.rows.length.toLocaleString()}</span></td></tr>${g.rows.map(rowHtml).join("")}`).join("");
  box.innerHTML = `<div class="dk-itwrap"><table class="dk-itable dk-fndt"><thead><tr>${write ? `<th class="ck"><input type="checkbox" id="dkFndAll" aria-label="Select all shown"></th>` : ""}<th>Severity</th><th>Finding</th><th>Owner</th><th>Due</th><th>Status</th><th>Source</th><th>First seen</th><th>Updated</th></tr></thead><tbody>${body}</tbody></table></div>${rows.length > shown.length ? `<div class="dk-nempty">Showing ${shown.length} of ${rows.length.toLocaleString()}. Narrow the filters, or export to get them all.</div>` : ""}`;
  const all1 = box.querySelector("#dkFndAll");
  if (all1) {
    all1.checked = shown.every((r) => S.sel.has(r.id));
    all1.onchange = () => { shown.forEach((r) => all1.checked ? S.sel.add(r.id) : S.sel.delete(r.id)); box.querySelectorAll("[data-sel]").forEach((x) => x.checked = all1.checked); paintBulk(); };
  }
  box.querySelectorAll("[data-sel]").forEach((x) => x.onchange = () => { x.checked ? S.sel.add(x.dataset.sel) : S.sel.delete(x.dataset.sel); paintBulk(); });
  box.querySelectorAll("[data-open]").forEach((b) => b.onclick = () => openFindingDetail(b.dataset.open));
}

function paintBulk() {
  const bar = S.el && S.el.querySelector("#dkFndBulk"); if (!bar) return;
  const n = S.sel.size;
  bar.hidden = !n || !canWrite(); if (bar.hidden) return;
  bar.innerHTML = `<b>${n} selected</b>${assignSelect('data-b="assign"', null, "Assign to...")}<select class="dk-isel" data-b="status" aria-label="Set status"><option value="">Set status...</option>${WORKFLOW_STATUSES.map((s) => `<option value="${s}">${cap(s)}</option>`).join("")}</select><button class="dk-tibtn" data-b="due">Set due date</button><button class="dk-tibtn" data-b="exc">Exception</button><button class="dk-tibtn" data-b="ticket">Create tickets</button><button class="dk-tibtn" data-b="clear">Clear selection</button>`;
  const ids = () => [...S.sel];
  bar.querySelector('[data-b="assign"]').onchange = (e) => { const ch = assignChange(e.target.value); if (!ch) return; withM((m) => afterBulk(applyTo(m, ids(), ch), ids())); };
  bar.querySelector('[data-b="status"]').onchange = (e) => { const v = e.target.value; e.target.value = ""; if (v) statusFlow(ids(), v); };
  bar.querySelector('[data-b="due"]').onclick = () => dueFlow(ids());
  bar.querySelector('[data-b="exc"]').onclick = () => exceptionFlow(ids());
  bar.querySelector('[data-b="ticket"]').onclick = () => ticketsFlow(ids());
  bar.querySelector('[data-b="clear"]').onclick = () => { S.sel.clear(); refresh(); };
}

// ---------- finding detail ----------
function scrollBox(el) {
  for (let p = el; p; p = p.parentElement) {
    const oy = getComputedStyle(p).overflowY;
    if ((oy === "auto" || oy === "scroll") && p.scrollHeight > p.clientHeight) return p;
  }
  return document.scrollingElement || document.documentElement;
}

/** Open one finding's detail page inside the Findings scene. */
export function openFindingDetail(id, ctx) {
  if (ctx) bind(ctx);
  if (!S.el || !S.ctx) return;
  const sb = scrollBox(S.el);
  if (!S.detailId) { S.scrollTop = sb.scrollTop; S.scrollEl = sb; }
  S.detailId = id;
  S.el.querySelector(".fq-q").hidden = true;
  S.el.querySelector(".fq-d").hidden = false;
  S.ctx.withGraph((m) => { paintDetail(m); sb.scrollTop = 0; });
}

function closeDetail() {
  if (!S.el) return;
  S.detailId = null;
  S.el.querySelector(".fq-d").hidden = true;
  S.el.querySelector(".fq-d").innerHTML = "";
  S.el.querySelector(".fq-q").hidden = false;
  S.ctx.withGraph((m) => { paintQueue(m); const sb = S.scrollEl || scrollBox(S.el); sb.scrollTop = S.scrollTop || 0; });
}

function assetsOf(m, e) {
  const out = [], seen = new Set();
  const rels = m.getRelationships ? m.getRelationships(e.id) : [];
  for (const r of rels) {
    const oid = r.fromId === e.id ? r.toId : r.fromId;
    const o = m.getEntity(oid);
    if (!o || o.type === "CONTROL" || seen.has(o.id)) continue;
    seen.add(o.id); out.push({ id: o.id, name: o.name, type: o.type, sev: o.severity, rel: r.type });
  }
  for (const nm of Array.isArray(e.data && e.data.assets) ? e.data.assets : []) {
    const name = String(nm || "").trim();
    if (!name || out.some((a) => String(a.name).toLowerCase() === name.toLowerCase())) continue;
    let hit = null;
    if (m.findEntity) for (const t of ["ASSET", "DOMAIN", "IP", "IDENTITY", "VENDOR", "ENDPOINT", "SERVICE", "SOFTWARE", "VULNERABILITY"]) { hit = m.findEntity(t, name); if (hit) break; }
    out.push(hit ? { id: hit.id, name: hit.name, type: hit.type, sev: hit.severity, rel: "affects" } : { id: null, name, type: "", rel: "" });
  }
  return out;
}

function paintDetail(m) {
  const box = S.el.querySelector(".fq-d"); if (!box) return;
  const ctx = S.ctx, IC = ctx.IC || {};
  const e = m && m.getEntity ? m.getEntity(S.detailId) : null;
  const draft = box.querySelector("#fqCmt") ? box.querySelector("#fqCmt").value : "";
  if (!e) {
    box.innerHTML = `<div class="fq-dtop"><button class="dk-tibtn" data-d="back">Back to queue</button></div><div class="dk-ovp"><div class="dk-nempty">This finding is no longer in the security graph.</div></div>`;
    box.querySelector('[data-d="back"]').onclick = closeDetail;
    return;
  }
  const now = Date.now(), d = e.data || {}, write = canWrite();
  const sev = String(e.severity || "").toLowerCase(), st = String(e.status || "new").toLowerCase();
  const sla = slaOf(e, now), chip = dueChip(sla, now, fmtDay);
  const title = cleanTitle(e) || "Untitled finding";
  const nameOf = nameOfFor(e);
  const kev = isKnownExploited(e, S.kev || undefined);
  const tool = String(d.tool || ""), toolName = tool ? (ctx.toolLabel ? ctx.toolLabel(tool) : null) : null;
  const sim = isSimulated(e);
  const badge = d.regressed && isOpenStatus(st)
    ? `<span class="fq-chip reg">Regressed${d.regressedAt ? " " + E(fmtDay(d.regressedAt)) : ""}</span>`
    : d.verifiedBy && d.resolution === "fixed" && !isOpenStatus(st) ? `<span class="fq-chip ok">Verified fixed by ${E((ctx.toolLabel && ctx.toolLabel(d.verifiedBy)) || d.verifiedBy)}${d.verifiedAt ? " " + E(fmtDay(d.verifiedAt)) : ""}</span>` : "";
  const dis = write ? "" : " disabled";
  const ev = evidenceLines(d, 50);
  const assets = assetsOf(m, e);
  const controls = Array.isArray(d.controls) ? d.controls.filter((c) => c && c.id) : [];
  const x = d.exception && typeof d.exception === "object" ? d.exception : null;
  const xActive = x && Number(x.expiresAt) > now;
  const riskEnt = x && x.riskId && m.getEntity ? m.getEntity(x.riskId) : null;
  const xh = Array.isArray(d.exceptionHistory) ? d.exceptionHistory.slice().reverse() : [];
  const tickets = (Array.isArray(d.tickets) ? d.tickets : []).filter((t) => t && /^https:\/\//i.test(String(t.url || "")));
  const tl = timelineSentences(timeline(e), { nameOf, toolName: ctx.toolLabel, fmtDate: fmtDay });
  const firstTs = toMs(e.createdAt);
  const sevTxt = sev ? SEV_LABEL[sev] || cap(sev) : "Unrated";
  const ov = d.severityOverride && d.severityOverride.reason ? `Changed from ${d.severityOverride.from || "none"} by ${nameOf(d.severityOverride.uid)}: ${d.severityOverride.reason}` : "";
  const pb = playbookFor(e, { kev });
  const pbHtml = `<div class="fq-sec"><div class="hd">Response playbook <span class="fq-mut" style="font-weight:400;text-transform:none;letter-spacing:0">${E(pb.title)}</span></div><ol class="fq-pb">${pb.steps.map((s) => `<li>${E(s)}</li>`).join("")}</ol><div class="fq-pbverify"><b>Verify:</b> ${E(pb.verify)}</div>${pb.references.length ? `<div class="fq-pbref">${pb.references.map((r) => `<span>${E((r.framework ? r.framework + " " : "") + r.id)}</span>`).join("")}</div>` : ""}</div>`;

  box.innerHTML = `
    <div class="fq-dtop"><button class="dk-tibtn" data-d="back">Back to queue</button><span class="fq-crumb">Findings / ${E(title)}</span><button class="dk-tibtn" data-d="graph">Graph record</button></div>
    ${write ? "" : `<div class="fq-note">${E(S.roleErr || "Read-only: viewers can't change findings.")}</div>`}
    <div class="dk-ovp">
      <div class="fq-dpills">${pill(sevC(sev), sevTxt)}${write ? `<button class="dk-tibtn" data-d="sev" style="height:26px;padding:0 9px;font-size:11.5px">Change severity</button>` : ""}${pill(stC(st), statusText(st, d.resolution))}${kev ? '<span class="fq-chip kev">CISA KEV</span>' : ""}${badge}${sim ? '<span class="dk-simchip" style="margin-left:0">Sample</span>' : ""}${e.type === "VULNERABILITY" ? '<span class="fq-chip vuln">Vulnerability</span>' : ""}</div>
      <h1 class="fq-dtitle">${E(title)}</h1>
      <div class="fq-dmeta">Source: ${E(toolName || tool || e.source || "manual")}${d.dataset ? " · Input: " + E(d.dataset) : ""} · First seen ${firstTs ? E(fmtDay(firstTs)) + " (" + E(ctx.agoISO(e.createdAt)) + ")" : "-"} · Updated ${E(ctx.agoISO(e.updatedAt))}</div>
      ${ov ? `<div class="fq-note">${E(ov)}</div>` : ""}
      <div class="fq-dctl">
        <div class="fq-fld"><span class="l">Status</span><select class="dk-isel" id="fqSt" aria-label="Status"${dis}>${WORKFLOW_STATUSES.map((s) => `<option value="${s}"${s === st ? " selected" : ""}>${cap(s)}</option>`).join("")}</select>${d.resolution ? `<span class="h">Resolution: ${E(RESOLUTION_LABEL[d.resolution] || d.resolution)}</span>` : ""}</div>
        <div class="fq-fld"><span class="l">Owner</span>${write ? assignSelect('id="fqOwn"', d.owner || null, "") : `<span class="fq-txt">${E(d.owner ? nameOf(d.owner) : "Unassigned")}</span>`}</div>
        <div class="fq-fld"><span class="l">Due</span><div class="fq-row"><span class="fq-due ${chip.cls}">${E(chip.text)}</span>${sla.dueAt && chip.cls !== "track" && chip.cls !== "none" ? `<span class="fq-mut">${E(fmtDay(sla.dueAt))}</span>` : ""}</div><span class="h">${E(slaBasis(e, S.policy, S.kev || undefined, fmtDay))}</span>${write ? `<div class="fq-row"><button class="dk-tibtn" data-d="due">Set due date</button>${Number.isFinite(toMs(d.dueAt)) ? `<button class="dk-tibtn" data-d="dueclear">Use SLA date</button>` : ""}</div>` : ""}</div>
      </div>
    </div>
    <div class="fq-dgrid">
      <div class="fq-dmain">
        <div class="dk-ovp">
          <div class="fq-sec"><div class="hd">Description</div>${d.description ? `<p class="fq-txt">${E(d.description)}</p>` : `<div class="fq-mut">The tool recorded no description.</div>`}</div>
          <div class="fq-sec"><div class="hd">Recommendation</div>${d.recommendation ? `<p class="fq-txt">${E(d.recommendation)}</p>` : `<div class="fq-mut">No recommendation recorded.</div>`}</div>
          ${pbHtml}
          <div class="fq-sec"><div class="hd">Affected assets (${assets.length})</div>${assets.length ? assets.map((a) => a.id ? `<button class="dk-relr" data-asset="${E(a.id)}"><span class="pdot" style="--c:${sevC(String(a.sev || "").toLowerCase())}"></span><span class="rn">${E(a.name || "-")}</span><span class="rt">${E(String(a.rel || "").replace(/_/g, " "))} ${E(m.getEntityTypeLabel ? m.getEntityTypeLabel(a.type) : a.type)}</span></button>` : `<div class="dk-relr" style="cursor:default"><span class="pdot" style="--c:#c2c8d4"></span><span class="rn">${E(a.name)}</span><span class="rt">not in the graph</span></div>`).join("") : `<div class="fq-mut">No affected assets recorded.</div>`}</div>
          ${controls.length ? `<div class="fq-sec"><div class="hd">Control references</div><div class="fq-ctl">${controls.map((c) => `<span>${E((c.framework ? c.framework + " " : "") + c.id)}</span>`).join("")}</div></div>` : ""}
          <div class="fq-sec"><div class="hd">Evidence${d.evidenceCount ? ` (${Number(d.evidenceCount).toLocaleString()} item${d.evidenceCount === 1 ? "" : "s"})` : ""}</div>${ev.lines.length ? `<pre class="fq-pre">${E(ev.lines.join("\n"))}</pre>${ev.more || ev.truncated ? `<div class="fq-mut" style="margin-top:6px">${ev.more ? `${ev.more.toLocaleString()} more line${ev.more === 1 ? "" : "s"} not shown. ` : ""}${ev.truncated ? "The tool trimmed some evidence to fit the graph's size limit." : ""}</div>` : ""}` : `<div class="fq-mut">No evidence recorded.</div>`}</div>
        </div>
        <div class="dk-ovp">
          <h2>${IC.note || ""} Activity</h2>
          <ul class="fq-tl">${firstTs ? `<li><span>First seen by ${E(toolName || tool || e.source || "a tool")}</span><span class="w">${E(fmtWhen(firstTs))}</span></li>` : ""}${tl.map((r) => `<li${r.kind === "comment" ? ' class="c"' : ""}><span>${E(r.text)}</span><span class="w">${E(fmtWhen(r.ts))}</span>${r.kind === "comment" ? `<div class="cm">${E(r.comment)}</div>` : ""}</li>`).join("")}</ul>
          ${write ? `<div class="fq-cbox"><label class="fq-fld"><span class="l">Add a comment</span><textarea id="fqCmt" maxlength="${COMMENT_MAX}" placeholder="Write a comment"></textarea></label><div class="fq-row"><span class="fq-cnt" id="fqCnt">0 / ${COMMENT_MAX}</span><button class="dk-tibtn" data-d="cmt">Comment</button></div></div>` : ""}
        </div>
      </div>
      <div class="fq-dside">
        <div class="dk-ovp">
          <h2>${IC.shield || ""} Risk exception</h2>
          ${x ? `<dl class="fq-kv"><dt>Status</dt><dd>${xActive ? "Active" : "Expired"}</dd><dt>Reason</dt><dd>${E(x.reason)}</dd><dt>Approved by</dt><dd>${E(x.approver)}</dd><dt>Expires</dt><dd>${E(fmtDay(x.expiresAt))}${xActive ? ` (in ${Math.max(0, Math.ceil((x.expiresAt - now) / DAY_MS))}d)` : ""}</dd>${x.riskId ? `<dt>Risk</dt><dd>${riskEnt ? `<button class="dk-tibtn" style="height:auto;padding:2px 7px;font-size:inherit" data-risk="${E(x.riskId)}">${E(riskEnt.name || x.riskId)}</button>` : E(x.riskId)}</dd>` : ""}<dt>Recorded</dt><dd>${E(nameOf(x.by))}${x.ts ? ", " + E(fmtDay(x.ts)) : ""}</dd></dl>` : `<div class="fq-mut" style="margin-bottom:10px">No active exception. Add one to accept this risk for a fixed period.</div>`}
          ${write ? `<div class="fq-row"><button class="dk-tibtn" data-d="exc">${x ? "Replace" : "Add exception"}</button>${x ? `<button class="dk-tibtn" data-d="revoke">Revoke</button>` : ""}</div>` : ""}
          ${xh.length ? `<div class="fq-sec" style="margin-top:12px"><div class="hd">History</div><ul class="fq-hist">${xh.map((h) => `<li>${E(h.reason || "")}<br><span class="fq-mut">Approved by ${E(h.approver || "-")}, until ${E(fmtDay(h.expiresAt))}. ${h.revokedAt ? `Revoked by ${E(nameOf(h.revokedBy))} ${E(fmtDay(h.revokedAt))}${h.revokeReason ? ": " + E(h.revokeReason) : ""}` : h.expiredAt ? `Expired ${E(fmtDay(h.expiredAt))}` : h.replacedAt ? `Replaced ${E(fmtDay(h.replacedAt))}` : ""}</span></li>`).join("")}</ul></div>` : ""}
        </div>
        <div class="dk-ovp">
          <h2>${IC.link || ""} Tickets</h2>
          ${tickets.length ? `<ul class="fq-tk">${tickets.map((t) => `<li><a href="${E(t.url)}" target="_blank" rel="noopener noreferrer">${E(t.label || t.url)}</a><br><span class="fq-mut">${E(nameOf(t.uid))}${t.ts ? ", " + E(fmtDay(t.ts)) : ""}</span></li>`).join("")}</ul>` : `<div class="fq-mut" style="margin-bottom:10px">No tickets linked.</div>`}
          ${write ? `<div class="fq-row"><button class="dk-tibtn" data-d="ticket">Create ticket</button><button class="dk-tibtn" data-d="link">Link existing</button></div>` : ""}
        </div>
        <div class="dk-ovp">
          <h2>${IC.wrench || ""} Source</h2>
          <dl class="fq-kv"><dt>Tool</dt><dd>${E(toolName || tool || e.source || "manual")}</dd>${d.category ? `<dt>Category</dt><dd>${E(d.category)}</dd>` : ""}${d.confidence != null ? `<dt>Confidence</dt><dd>${E(d.confidence)}</dd>` : ""}<dt>First seen</dt><dd>${firstTs ? E(fmtWhen(firstTs)) : "-"}</dd><dt>Last updated</dt><dd>${Number.isFinite(toMs(e.updatedAt)) ? E(fmtWhen(toMs(e.updatedAt))) : "-"}</dd></dl>
          ${toolName ? `<button class="dk-tibtn" data-d="tool">Open ${E(toolName)}</button>` : ""}
        </div>
      </div>
    </div>`;
  const $ = (s) => box.querySelector(s);
  const on = (k, fn) => { const b = $(`[data-d="${k}"]`); if (b) b.onclick = fn; };
  const ids = [e.id];
  on("back", closeDetail);
  on("graph", () => ctx.openEntityDrawer(e.id));
  on("tool", () => ctx.openTool(tool));
  box.querySelectorAll("[data-asset]").forEach((b) => b.onclick = () => ctx.openEntityDrawer(b.dataset.asset));
  box.querySelectorAll("[data-risk]").forEach((b) => b.onclick = () => ctx.openEntityDrawer(b.dataset.risk));
  if (!write) return;
  on("sev", () => formChange(ids, {
    title: "Change severity", desc: "Tool re-runs keep your severity. The reason is kept in the history.", submitText: "Change severity",
    fields: [
      { key: "severity", label: "Severity", type: "select", required: true, value: sev, options: SEVERITY_LEVELS.map((s) => [s, SEV_LABEL[s]]) },
      { key: "reason", label: "Reason", type: "textarea", required: true, maxlength: 500, placeholder: "Why the severity changes" },
    ],
  }, (v) => (v.severity === sev ? "Pick a different severity." : { op: "severity", severity: v.severity, reason: v.reason }), "Severity changed"));
  $("#fqSt").onchange = (ev) => { const to = ev.target.value; ev.target.value = st; statusFlow(ids, to); };
  const own = $("#fqOwn"); if (own) own.onchange = (ev) => { const ch = assignChange(ev.target.value); if (ch) withM((g) => { const s = applyTo(g, ids, ch); toast(s.updated ? (ch.owner ? "Assigned to " + (ch.owner === myUid() ? "you" : memberName(ch.owner, S.members, {})) : "Unassigned") : s.firstError || "No change"); refresh(); }); };
  on("due", () => dueFlow(ids, e));
  on("dueclear", async () => {
    const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Use the SLA due date?", "Removes the manual due date; the policy date applies again.", { submitText: "Use SLA date" }) : false;
    if (ok) withM((g) => { const s = applyTo(g, ids, { op: "due", dueAt: null }); toast(s.updated ? "Manual due date cleared" : s.firstError || "No change"); refresh(); });
  });
  on("exc", () => exceptionFlow(ids, e));
  on("revoke", () => formChange(ids, {
    title: "Revoke risk exception", desc: "The finding returns to the queue. A finding resolved as risk accepted reopens.", submitText: "Revoke", danger: true,
    fields: [{ key: "reason", label: "Reason", type: "textarea", maxlength: 500, placeholder: "Why it is revoked" }],
  }, (v) => ({ op: "revokeException", reason: v.reason }), "Risk exception revoked"));
  on("ticket", () => ticketsFlow(ids));
  on("link", () => formChange(ids, {
    title: "Link an existing ticket", submitText: "Link ticket",
    fields: [
      { key: "url", label: "Ticket link", type: "text", required: true, placeholder: "https://", help: "The full https link to the issue or ticket." },
      { key: "label", label: "Label", type: "text", maxlength: 120, placeholder: "Ticket key" },
    ],
  }, (v) => ({ op: "ticket", url: v.url, label: v.label }), "Ticket linked"));
  const ta = $("#fqCmt"), cnt = $("#fqCnt");
  if (ta) {
    ta.value = draft;
    const upd = () => { cnt.textContent = `${ta.value.length.toLocaleString()} / ${COMMENT_MAX.toLocaleString()}`; };
    ta.oninput = upd; upd();
    on("cmt", () => withM((g) => {
      const cur = g.getEntity(e.id); if (!cur) return;
      const r = applyChange(cur, { op: "comment", text: ta.value }, actx());
      if (r.error) { toast(r.error); return; }
      g.updateEntity(e.id, r.updates);
      ta.value = ""; toast("Comment added"); refresh();
    }));
  }
}

// ---------- SLA policy (Settings) ----------
/** Append the workspace SLA policy panel to the Settings grid. */
export function renderSlaSettings(grid, ctx) {
  if (!grid) return;
  injectStyle(); bind(ctx);
  const IC = ctx.IC || {};
  const panel = document.createElement("div");
  panel.className = "dk-ovp fq-sla";
  grid.appendChild(panel);
  const src = (k) => (k === "critical" ? SLA_SOURCES.critical : k === "kev" ? SLA_SOURCES.kev : SLA_SOURCES.other.charAt(0).toUpperCase() + SLA_SOURCES.other.slice(1));
  const paint = (msg, kind) => {
    const editable = canEditSla();
    const known = isPersonal() || S.role != null;
    const p = S.policy;
    panel.innerHTML = `<h2>${IC.gauge || ""} Remediation SLA</h2>
      <p class="fq-slad">Days to fix an open finding, counted from when it was first seen. Known-exploited findings use the KEV target when it is sooner. ${isPersonal() ? "Applies to your personal workspace." : "Shared by everyone in this workspace."} Leave a box empty for no SLA.</p>
      ${SLA_KEYS.map((k) => `<div class="dk-setrow"><div class="m"><div class="t">${E(SLA_LABEL[k])}</div><div class="s">${E(src(k))}</div></div><input class="dk-setin" type="number" inputmode="numeric" min="1" max="3650" step="1" data-k="${k}" value="${p[k] == null ? "" : p[k]}" placeholder="None" aria-label="${E(SLA_LABEL[k])} days"${editable ? "" : " disabled"}><span class="u">days</span></div>`).join("")}
      ${S.kevState === "failed" ? `<div class="fq-note warn" style="margin:10px 0 0">KEV matching is unavailable: the CISA KEV index could not be loaded. Only findings their tool marked as known-exploited get the KEV target.</div>` : S.kevState === "ok" && S.kevMeta ? `<div class="fq-mut" style="margin-top:10px">KEV matching uses the CISA catalog index (${S.kevMeta.count.toLocaleString()} CVEs${S.kevMeta.updated ? ", mirrored " + E(String(S.kevMeta.updated).slice(0, 10)) : ""}).</div>` : ""}
      ${!known ? `<div class="fq-note" style="margin:10px 0 0">Checking your role in this workspace...</div>` : editable ? "" : `<div class="fq-note" style="margin:10px 0 0">${E(S.roleErr || "Read-only: only a workspace owner or admin can change the SLA policy.")}</div>`}
      ${S.policyLoaded ? "" : `<div class="fq-mut" style="margin-top:10px">No saved policy loaded, so the defaults shown apply.</div>`}
      <div class="fq-slamsg${kind ? " " + kind : ""}" role="status">${E(msg || "")}</div>
      ${editable ? `<div class="fq-row" style="margin-top:10px"><button class="dk-settog" data-a="save">Save policy</button><button class="dk-settog" data-a="reset">Reset to defaults</button></div>` : ""}`;
    // Errors leave the typed values in place; only a successful save repaints.
    const say = (m, kind) => { const box = panel.querySelector(".fq-slamsg"); box.className = "fq-slamsg" + (kind ? " " + kind : ""); box.textContent = m; };
    const save = async (policy, okMsg) => {
      const btns = panel.querySelectorAll("[data-a]"); btns.forEach((b) => b.disabled = true);
      say("Saving...");
      try {
        await setConfig(SLA_CONFIG, policy);
        S.policy = normalizePolicy(policy); S.policyLoaded = true;
        toast(okMsg); paint(okMsg + ".", "ok");
      } catch (err) {
        const m = (err && err.message) || String(err);
        btns.forEach((b) => b.disabled = false);
        say(`Not saved: ${m} The policy in effect is unchanged${S.policyLoaded ? "" : " (the defaults)"}.`, "err");
      }
    };
    const sv = panel.querySelector('[data-a="save"]');
    if (sv) sv.onclick = () => {
      const pol = {};
      for (const k of SLA_KEYS) {
        const raw = String(panel.querySelector(`[data-k="${k}"]`).value || "").trim();
        if (!raw) { pol[k] = null; continue; }
        const n = Number(raw);
        if (!Number.isInteger(n) || n < 1 || n > 3650) { say(`${SLA_LABEL[k]}: enter whole days from 1 to 3650, or leave it empty for no SLA.`, "err"); return; }
        pol[k] = n;
      }
      save(pol, "SLA policy saved");
    };
    const rs = panel.querySelector('[data-a="reset"]');
    if (rs) rs.onclick = async () => {
      const ok = typeof window.dnConfirm === "function" ? await window.dnConfirm("Reset the SLA policy?", "Every severity and the KEV target return to the defaults for this workspace.", { submitText: "Reset", danger: true }) : false;
      if (ok) save({ ...SLA_DEFAULTS }, "SLA policy reset to defaults");
    };
  };
  paint("");
  const k = S.wsk;
  Promise.all([loadTeam(), loadKev(), loadPolicy()]).then(() => { if (k === S.wsk && panel.isConnected && !panel.contains(document.activeElement)) paint(""); });
}
