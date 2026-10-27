// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Shared kit for the Deck's native spaces (Personal / Enterprise): scoped styles,
// escaping, a per-space run history, and small render helpers. Native tools render
// straight into the Deck DOM and call the pure engines; nothing here loads a console
// page in an iframe.

export const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
export const toast = (m) => { try { (window.showToast || window.dnToast || (() => {}))(m); } catch (_) {} };

export const SEV = {
  critical: { c: "#b00020", t: "Critical", r: 4 }, high: { c: "#d9480f", t: "High", r: 3 },
  medium: { c: "#b58100", t: "Medium", r: 2 }, low: { c: "#2f7d9e", t: "Low", r: 1 }, info: { c: "#8a93a6", t: "Info", r: 0 },
};
export const sevPill = (sev) => { const s = SEV[sev] || SEV.info; return `<span class="ns-pill" style="background:${s.c}">${s.t}</span>`; };
export const GRADE_C = { A: "#2f9e56", B: "#4c9a2a", C: "#b58100", D: "#d9480f", F: "#b00020", "N/A": "#667085" };

export function ago(ts) {
  const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  return Math.round(s / 86400) + " d ago";
}

export function download(name, text, type = "application/json") {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

// localStorage is shared by every account that signs in on this browser, so saved lists and run
// history are keyed by the signed-in uid (window.__dnUid, kept by auth.js). Data saved before this
// moves to the first signed-in account that opens it; guests and Test Mode (a per-session uid) keep the plain key.
function skey(space, name) {
  const plain = "dn_space_" + space + "_" + name;
  let u = null; try { u = window.__dnUid || null; } catch (_) {}
  if (!u || /^(test|app-guest)-/.test(u)) return plain;
  const k = "dn_space_u_" + u + "_" + space + "_" + name;
  try { if (localStorage.getItem(k) == null) { const old = localStorage.getItem(plain); if (old != null) { localStorage.setItem(k, old); localStorage.removeItem(plain); } } } catch (_) {}
  return k;
}

// ---- run history: what the home screens summarise. Real runs only. ----
const HKEY = (space) => skey(space, "runs");
const HMAX = 200;
export function readRuns(space) {
  try { const v = JSON.parse(localStorage.getItem(HKEY(space)) || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; }
}
// run = { tool, target, summary, level: "good"|"warn"|"bad", score?, counts? }
export function recordRun(space, run) {
  const list = readRuns(space).filter((r) => !(r.tool === run.tool && r.target === run.target));
  list.unshift({ ...run, at: Date.now() });
  try { localStorage.setItem(HKEY(space), JSON.stringify(list.slice(0, HMAX))); } catch (_) {}
  try { window.dispatchEvent(new CustomEvent("dn-space-run", { detail: { space } })); } catch (_) {}
}
export function clearRuns(space) { try { localStorage.removeItem(HKEY(space)); } catch (_) {} }

// Saved per-space lists (domains to watch, etc.).
export function readList(space, name) {
  try { const v = JSON.parse(localStorage.getItem(skey(space, name)) || "[]"); return Array.isArray(v) ? v : []; } catch (_) { return []; }
}
export function writeList(space, name, v) { try { localStorage.setItem(skey(space, name), JSON.stringify(v)); } catch (_) {} }

// Run async jobs with a concurrency cap; onEach(result, i) fires as each settles.
export async function pool(items, n, fn, onEach) {
  const out = new Array(items.length); let next = 0;
  const worker = async () => {
    while (next < items.length) {
      const i = next++;
      try { out[i] = await fn(items[i], i); } catch (e) { out[i] = { error: String((e && e.message) || e) }; }
      if (onEach) onEach(out[i], i);
    }
  };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, worker));
  return out;
}

// Read dropped/picked files as text, skipping binaries and anything huge.
export async function readFiles(fileList, { maxBytes = 2 * 1024 * 1024, maxFiles = 2000 } = {}) {
  const out = [], skipped = [];
  for (const f of Array.from(fileList || [])) {
    const path = f.webkitRelativePath || f.name;
    if (/(^|\/)(node_modules|\.git|dist|build|vendor)\//.test(path)) { skipped.push(path); continue; }
    // cap AFTER dropping dependency folders: a picked repo lists node_modules first, and a cap applied
    // before the filter could fill up with them and never read the project's own files
    if (out.length >= maxFiles) { skipped.push(path); continue; }
    if (f.size > maxBytes) { skipped.push(path); continue; }
    const text = await f.text();
    if (/\u0000/.test(text.slice(0, 4000))) { skipped.push(path); continue; }
    out.push({ path, text });
  }
  return { files: out, skipped };
}

let injected = false;
export function injectStyle() {
  if (injected) return; injected = true;
  const st = document.createElement("style"); st.id = "ns-css";
  st.textContent = `
.ns{--ns-acc:var(--dk-acc,#2552c6);--ns-tx:var(--dk-tx,#1a2233);--ns-tx2:var(--dk-tx2,#4a5263);--ns-mut:var(--dk-mut,#6b7589);--ns-line:var(--dk-line,#e3e6ec);--ns-surf:var(--dk-surf,#fff);--ns-bg:var(--dk-bg,#f4f6fa);color:var(--ns-tx);font-size:14px;line-height:1.5;padding:0 0 40px}
.ns *{box-sizing:border-box}
.ns-hero{position:relative;overflow:hidden;border-radius:14px;padding:26px 28px 22px;margin:0 0 18px;color:#fff;background:var(--ns-hero)}
.ns-hero::after{content:"";position:absolute;right:-60px;top:-80px;width:320px;height:320px;border-radius:50%;background:radial-gradient(circle,rgba(255,255,255,.18),transparent 65%);pointer-events:none}
.ns-hero .k{font-size:11px;font-weight:800;letter-spacing:.14em;text-transform:uppercase;opacity:.85}
.dk .ns .ns-hero h1,.ns .ns-hero h1{font-size:28px;line-height:1.15;margin:6px 0 6px;letter-spacing:-.02em;color:#fff!important}
.dk[data-ui=deck] .ns-hero{filter:invert(1) hue-rotate(180deg)}
.ns-hero p{margin:0;max-width:72ch;opacity:.9;font-size:14.5px}
.ns-tabs{display:flex;gap:6px;flex-wrap:wrap;margin:0 0 18px;padding:6px;border:1px solid var(--ns-line);border-radius:12px;background:var(--ns-surf)}
.ns-tab{appearance:none;border:0;background:transparent;color:var(--ns-tx2);font:inherit;font-size:13.5px;font-weight:600;padding:9px 14px;border-radius:8px;cursor:pointer;white-space:nowrap}
.ns-tab:hover{background:var(--ns-bg);color:var(--ns-tx)}
.ns-tab.on{background:var(--ns-acc);color:#fff}
.ns-card{background:var(--ns-surf);border:1px solid var(--ns-line);border-radius:12px;padding:18px 20px;margin:0 0 16px}
.ns-card>h2{display:flex;align-items:center;gap:10px;font-size:16px;margin:0 0 4px}
.ns-card>h2 .r{margin-left:auto;font-size:12px;font-weight:600;color:var(--ns-mut)}
.ns-sub{color:var(--ns-mut);margin:0 0 14px;font-size:13.5px;max-width:80ch}
.ns-form{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-start}
.ns-in,.ns-ta{flex:1;min-width:220px;font:inherit;font-size:14px;padding:10px 12px;border:1px solid var(--ns-line);border-radius:8px;background:var(--ns-bg);color:var(--ns-tx)}
.ns-ta{width:100%;min-height:150px;resize:vertical;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.ns-in:focus,.ns-ta:focus{outline:2px solid color-mix(in srgb,var(--ns-acc) 45%,transparent);outline-offset:1px}
.ns-help{color:var(--ns-mut);font-size:12.5px;margin:8px 2px 0}
.ns-btn{appearance:none;font:inherit;font-size:13.5px;font-weight:700;border:1px solid var(--ns-acc);background:var(--ns-acc);color:#fff;padding:10px 18px;border-radius:8px;cursor:pointer;white-space:nowrap}
.ns-btn:hover{filter:brightness(1.08)}
.ns-btn:disabled{opacity:.55;cursor:default}
.ns-btn.ghost{background:var(--ns-surf);color:var(--ns-tx);border-color:var(--ns-line);font-weight:600}
.ns-btn.sm{padding:6px 12px;font-size:12.5px}
.ns-card .dn-sink-btn{appearance:none;font:inherit;font-size:12.5px;font-weight:600;background:var(--ns-surf);color:var(--ns-tx);border:1px solid var(--ns-line);padding:6px 12px;border-radius:8px;cursor:pointer;white-space:nowrap}
.ns-card .dn-sink-btn:hover{filter:brightness(1.08)}
.ns-card .dn-sink .muted{color:var(--ns-mut)}
.ns-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-top:12px}
.ns-seg{display:inline-flex;border:1px solid var(--ns-line);border-radius:8px;overflow:hidden}
.ns-seg button{appearance:none;border:0;background:var(--ns-surf);color:var(--ns-tx2);font:inherit;font-size:13px;font-weight:600;padding:8px 14px;cursor:pointer}
.ns-seg button.on{background:var(--ns-acc);color:#fff}
.ns-pill{display:inline-block;font-size:11px;font-weight:800;color:#fff;padding:2px 9px;border-radius:999px;min-width:46px;text-align:center;white-space:nowrap}
.ns-kpis{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:0 0 16px}
.ns-kpi{background:var(--ns-surf);border:1px solid var(--ns-line);border-left:4px solid var(--c,var(--ns-acc));border-radius:10px;padding:14px 16px}
.ns-kpi .v{font-size:26px;font-weight:800;letter-spacing:-.02em;color:var(--c,var(--ns-tx))}
.ns-kpi .l{font-size:12px;color:var(--ns-mut);font-weight:600}
@media(max-width:900px){.ns-kpis{grid-template-columns:repeat(2,minmax(0,1fr))}}
.ns-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px}
.ns-tile{appearance:none;text-align:left;font:inherit;color:inherit;background:var(--ns-surf);border:1px solid var(--ns-line);border-top:4px solid var(--c,var(--ns-acc));border-radius:12px;padding:16px;cursor:pointer;display:flex;flex-direction:column;gap:6px}
.ns-tile:hover{border-color:var(--c,var(--ns-acc));box-shadow:0 6px 18px rgba(16,24,40,.08)}
.ns-tile b{font-size:15px}
.ns-tile span{color:var(--ns-mut);font-size:13px}
.ns-tile em{font-style:normal;font-size:12px;font-weight:700;color:var(--c,var(--ns-acc));margin-top:auto}
.ns-tbl{width:100%;border-collapse:collapse;font-size:13px}
.ns-tbl th{text-align:left;font-size:11px;letter-spacing:.06em;text-transform:uppercase;color:var(--ns-mut);font-weight:700;padding:8px 10px;border-bottom:1px solid var(--ns-line)}
.ns-tbl td{padding:9px 10px;border-bottom:1px solid var(--ns-line);vertical-align:top}
.ns-tbl tr:last-child td{border-bottom:0}
.ns-tbl .mono,.ns-mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px;word-break:break-all}
.ns-scroll{overflow:auto;max-height:520px;border:1px solid var(--ns-line);border-radius:10px}
.ns-check{display:flex;gap:12px;padding:11px 14px;border-left:4px solid transparent;border-bottom:1px solid var(--ns-line)}
.ns-check:last-child{border-bottom:0}
.ns-check.fail{border-left-color:#b00020;background:color-mix(in srgb,#b00020 5%,transparent)}
.ns-check.warn{border-left-color:#b58100}
.ns-check.pass{border-left-color:#2f9e56}
.ns-check .n{font-weight:700}
.ns-check .d{font-size:13px}
.ns-check .a{font-size:12.5px;color:var(--ns-mut);margin-top:2px}
.ns-cat{border:1px solid var(--ns-line);border-radius:10px;overflow:hidden;margin-bottom:10px}
.ns-cat>h3{display:flex;gap:10px;align-items:center;margin:0;padding:10px 14px;font-size:14px;background:var(--ns-bg);border-bottom:1px solid var(--ns-line)}
.ns-cat>h3 .s{margin-left:auto;font-size:12.5px;font-weight:700}
.ns-score{display:flex;align-items:center;gap:20px;flex-wrap:wrap}
.ns-ring{width:88px;height:88px;border-radius:50%;display:grid;place-items:center;flex:none;background:conic-gradient(var(--g) calc(var(--p)*1%),var(--ns-line) 0)}
.ns-ring .in{width:68px;height:68px;border-radius:50%;background:var(--ns-surf);display:grid;place-items:center;font-size:26px;font-weight:800;color:var(--g)}
.ns-grade{display:inline-grid;place-items:center;width:30px;height:30px;border-radius:8px;color:#fff;font-weight:800}
.ns-note{border:1px solid var(--ns-line);border-left:4px solid #b58100;border-radius:8px;padding:10px 14px;font-size:12.5px;color:var(--ns-tx2);margin-top:12px}
.ns-empty{text-align:center;color:var(--ns-mut);padding:26px 10px}
.ns-spin{display:inline-block;width:15px;height:15px;border:2px solid color-mix(in srgb,var(--ns-acc) 30%,transparent);border-top-color:var(--ns-acc);border-radius:50%;animation:nsSpin .7s linear infinite;vertical-align:-3px;margin-right:8px}
@keyframes nsSpin{to{transform:rotate(360deg)}}
.ns-drop{border:2px dashed var(--ns-line);border-radius:10px;padding:18px;text-align:center;color:var(--ns-mut);font-size:13px}
.ns-drop.over{border-color:var(--ns-acc);background:color-mix(in srgb,var(--ns-acc) 6%,transparent)}
.ns-list{list-style:none;margin:0;padding:0}
.ns-list li{display:flex;gap:10px;align-items:center;padding:9px 2px;border-bottom:1px solid var(--ns-line);font-size:13px}
.ns-list li:last-child{border-bottom:0}
.ns-list .t{margin-left:auto;color:var(--ns-mut);font-size:12px;white-space:nowrap}
.ns-dot{width:9px;height:9px;border-radius:50%;flex:none;background:var(--c,#8a93a6)}
.ns-two{display:grid;grid-template-columns:minmax(0,1.4fr) minmax(0,1fr);gap:16px}
@media(max-width:1000px){.ns-two{grid-template-columns:1fr}}
.ns-steps{counter-reset:s;list-style:none;margin:0;padding:0}
.ns-steps li{counter-increment:s;display:flex;gap:12px;align-items:flex-start;padding:10px 0;border-bottom:1px solid var(--ns-line);font-size:13.5px}
.ns-steps li:last-child{border-bottom:0}
.ns-steps li::before{content:counter(s);flex:none;display:grid;place-items:center;width:24px;height:24px;border-radius:50%;background:var(--ns-bg);border:1px solid var(--ns-line);font-weight:800;font-size:12px}
.ns-steps li.done::before{content:"\\2713";background:#2f9e56;border-color:#2f9e56;color:#fff}
.ns-steps li button{margin-left:auto}
`;
  document.head.appendChild(st);
}
