// Monitors scene (Deck D4): schedule server-side security checks that keep running when
// nobody has the Deck open, and route their alerts to Slack / Teams / Discord / a signed
// webhook. Talks to the MonitorDO through deck/monitor-client.js. The first check type is
// certificate expiry (real CT-log lookups graded by the posture engine); more are added
// server-side as worker-safe engines are extracted.
import { monitorApi, monitoringAvailable } from "./monitor-client.js";

const S = { ctx: null, el: null, data: null, adding: false, busy: false };
const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const toast = (m, t) => { try { S.ctx && S.ctx.toast && S.ctx.toast(m, t); } catch (_) {} };
const ago = (ts) => { if (!ts) return "never"; const s = Math.floor((Date.now() - ts) / 1000); if (s < 60) return s + "s ago"; if (s < 3600) return Math.floor(s / 60) + "m ago"; if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago"; };
const CHANNELS = [["slack", "Slack"], ["teams", "Microsoft Teams"], ["discord", "Discord"], ["webhook", "Signed webhook"]];

function injectStyle() {
  if (document.getElementById("mon-css")) return;
  const st = document.createElement("style"); st.id = "mon-css";
  st.textContent = `
.mon-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 14px;line-height:1.5}
.mon-row{border:1px solid rgba(23,33,56,.12);border-radius:10px;padding:12px 14px;margin:0 0 9px}
.mon-top{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.mon-name{font-weight:650;font-size:13.5px;color:#141c2e}
.mon-meta{color:#5a6680;font-size:12px}
.mon-pill{font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 8px;background:rgba(23,33,56,.07);color:#45506a}
.mon-pill.paused{background:rgba(245,146,11,.14);color:#9a5a00}
.mon-actions{margin-left:auto;display:flex;gap:6px}
.mon-btn{appearance:none;border:1px solid rgba(23,33,56,.16);background:#fff;border-radius:7px;font:inherit;font-size:12px;font-weight:600;color:#2a3450;padding:4px 10px;cursor:pointer}
.mon-btn:hover{border-color:var(--dk-acc,#2552c6);color:var(--dk-acc,#2552c6)}
.mon-btn.danger:hover{border-color:#c62828;color:#c62828}
.mon-btn.pri{background:var(--dk-acc,#2552c6);border-color:var(--dk-acc,#2552c6);color:#fff}
.mon-form{border:1px dashed rgba(37,82,198,.4);border-radius:10px;padding:14px;margin:0 0 16px;background:rgba(37,82,198,.03)}
.mon-form h3{margin:0 0 10px;font-size:13.5px}
.mon-field{margin:0 0 10px}
.mon-field label{display:block;font-size:12px;font-weight:600;color:#2a3450;margin:0 0 3px}
.mon-field .hint{font-size:11.5px;color:#5a6680;margin:3px 0 0}
.mon-field input,.mon-field textarea,.mon-field select{width:100%;font:inherit;font-size:13px;border:1px solid rgba(23,33,56,.18);border-radius:7px;padding:7px 9px;box-sizing:border-box}
.mon-field textarea{min-height:52px;resize:vertical}
.mon-chrow{display:flex;gap:8px}.mon-chrow select{flex:0 0 150px}.mon-chrow input{flex:1}
.mon-panel{margin:18px 0 0}
.mon-panel h2{font-size:14px;margin:0 0 8px}
.mon-log{font-size:12px;color:#45506a;border-top:1px dashed rgba(23,33,56,.1);padding:5px 0}
.mon-log b{color:#141c2e;font-weight:650}
.mon-off{font-size:12.5px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:11px 13px;line-height:1.5}
`;
  document.head.appendChild(st);
}

export function mountMonitors(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el; S.adding = false;
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>Monitors</h1><p>Scheduled security checks that run on the server and keep running when the Deck is closed. Only real changes raise an alert, routed to Slack, Teams, Discord or a signed webhook.</p></div></div>
    <div class="dk-ovp" id="monBody"><div class="dk-loading"><span class="sp"></span>Loading monitors…</div></div>`;
  load();
}

// repaint on graph sync is irrelevant here (monitors live server-side); kept for the
// scene contract so the router can call it harmlessly.
export function repaintMonitors() {}

async function load() {
  const box = S.el && S.el.querySelector("#monBody"); if (!box) return;
  if (!monitoringAvailable()) { box.innerHTML = `<div class="mon-off">Monitoring is not available on this build — it needs the cloud proxy. Nothing to configure yet.</div>`; return; }
  try {
    S.data = await monitorApi({ op: "list" });
    paint();
  } catch (e) {
    box.innerHTML = `<div class="mon-off">${E(e.message || String(e))}</div>`;
  }
}

function paint() {
  const box = S.el && S.el.querySelector("#monBody"); if (!box || !S.data) return;
  const mons = S.data.monitors || [];
  const monHtml = mons.length ? mons.map((m) => {
    const dom = (m.config && m.config.domains) || [];
    return `<div class="mon-row" data-id="${E(m.id)}">
      <div class="mon-top">
        <span class="mon-name">${E(m.name)}</span>
        <span class="mon-pill">${E(m.type)}</span>
        ${m.paused ? '<span class="mon-pill paused">Paused</span>' : ""}
        <span class="mon-meta">${dom.length ? E(dom.slice(0, 3).join(", ")) + (dom.length > 3 ? ` +${dom.length - 3}` : "") : ""} · every ${Math.round((m.intervalMs || 0) / 60000)}m · last run ${E(ago(m.lastRunAt))} · ${m.lastResultCount || 0} open · ${(m.channels || []).length} channel${(m.channels || []).length === 1 ? "" : "s"}</span>
        <span class="mon-actions">
          <button class="mon-btn" data-act="run">Run now</button>
          <button class="mon-btn" data-act="pause">${m.paused ? "Resume" : "Pause"}</button>
          <button class="mon-btn danger" data-act="del">Delete</button>
        </span>
      </div>
    </div>`;
  }).join("") : `<div class="dk-nempty">No monitors yet. Add a certificate monitor to get alerted before a cert expires.</div>`;

  box.innerHTML = `
    <p class="mon-sub">${mons.length.toLocaleString()} monitor${mons.length === 1 ? "" : "s"}. Monitors run on the server's own schedule; alerts fire only when something changes.</p>
    <div style="margin:0 0 14px;display:flex;gap:8px;flex-wrap:wrap"><button class="mon-btn pri" id="monAdd">Add certificate monitor</button><button class="mon-btn" id="monAddKev">Add KEV/EPSS watch</button></div>
    <div id="monFormSlot"></div>
    ${monHtml}
    ${logPanel("Recent runs", (S.data.history || []).slice(0, 8), (h) => `<b>${E((S.data.monitors.find((m) => m.id === h.id) || {}).name || h.id)}</b> — ${h.error ? ("error: " + E(h.error)) : `${h.found} open, ${h.added} new, ${h.changed} changed, ${h.alerted} alerted${h.graphError ? ", not synced to Findings: " + E(h.graphError) : ""}`} · ${E(ago(h.at))}`)}
    ${logPanel("Delivery log", (S.data.deliveries || []).slice(0, 8), (d) => `<b>${E(d.type)}</b> ${d.ok ? "delivered" : "failed"} (${d.status})${d.error ? " — " + E(d.error) : ""} · ${E(ago(d.at))}`)}`;

  box.querySelector("#monAdd").onclick = () => { const was = S.adding && S.kind === "cert-expiry"; S.kind = "cert-expiry"; S.adding = !was; renderForm(); };
  box.querySelector("#monAddKev").onclick = () => { const was = S.adding && S.kind === "kev-epss"; S.kind = "kev-epss"; S.adding = !was; renderForm(); };
  if (S.adding) renderForm();
  box.querySelectorAll(".mon-row").forEach((row) => row.querySelector(".mon-actions").onclick = (e) => {
    const b = e.target.closest("[data-act]"); if (!b) return;
    const id = row.dataset.id, act = b.dataset.act;
    if (act === "run") act_run(id);
    else if (act === "pause") act_pause(id, row);
    else if (act === "del") act_del(id, row);
  });
}

function logPanel(title, rows, fmt) {
  if (!rows.length) return "";
  return `<div class="mon-panel"><h2>${E(title)}</h2>${rows.map((r) => `<div class="mon-log">${fmt(r)}</div>`).join("")}</div>`;
}

function renderForm() {
  const slot = S.el && S.el.querySelector("#monFormSlot"); if (!slot) return;
  if (!S.adding) { slot.innerHTML = ""; return; }
  const kev = S.kind === "kev-epss";
  const specific = kev
    ? `<div class="mon-field"><label for="mfEpss">EPSS alert floor (0–1)</label><input id="mfEpss" type="number" min="0" max="1" step="0.05" placeholder="0.5"><p class="hint">A CVE in your graph alerts when it is in the CISA KEV catalogue, or its EPSS exploit-prediction score is at or above this floor. Nothing is sent anywhere; the match runs against the current feeds.</p></div>`
    : `<div class="mon-field"><label for="mfDomains">Domains</label><textarea id="mfDomains" placeholder="one per line or comma-separated" spellcheck="false"></textarea><p class="hint">Hostnames to watch, e.g. test.darknode.ai. Certificate transparency logs are checked; nothing is sent to the domains.</p></div>
    <div class="mon-field"><label for="mfWarn">Warn when expiring within (days)</label><input id="mfWarn" type="number" min="1" max="365" placeholder="21"></div>`;
  slot.innerHTML = `<div class="mon-form">
    <h3>${kev ? "New KEV / EPSS watch" : "New certificate-expiry monitor"}</h3>
    <div class="mon-field"><label for="mfName">Name</label><input id="mfName" placeholder="${kev ? "Known-exploited vulnerabilities" : "Public certificates"}" autocomplete="off"></div>
    ${specific}
    <div class="mon-field"><label for="mfInt">Check interval (minutes)</label><input id="mfInt" type="number" min="15" max="10080" placeholder="1440"></div>
    <div class="mon-field"><label for="mfChUrl">Alert channel</label>
      <div class="mon-chrow"><select id="mfChType" aria-label="Channel type">${CHANNELS.map(([v, l]) => `<option value="${v}">${l}</option>`).join("")}</select><input id="mfChUrl" placeholder="incoming webhook URL" autocomplete="off" spellcheck="false"></div>
      <p class="hint">Optional. For a signed webhook you can add a shared secret below; Slack/Teams/Discord use their own incoming-webhook URL.</p>
    </div>
    <div class="mon-field"><label for="mfChSecret">Webhook signing secret (signed webhook only)</label><input id="mfChSecret" placeholder="leave blank unless using a signed webhook" autocomplete="off"></div>
    <div style="display:flex;gap:8px"><button class="mon-btn pri" id="mfSave">Save monitor</button><button class="mon-btn" id="mfTest">Test channel</button><button class="mon-btn" id="mfCancel">Cancel</button></div>
  </div>`;
  const $ = (s) => slot.querySelector(s);
  $("#mfCancel").onclick = () => { S.adding = false; renderForm(); };
  $("#mfSave").onclick = () => saveMonitor(slot);
  $("#mfTest").onclick = () => testChannel(slot);
}

export function hostOf(x) {
  let h = String(x || "").trim().toLowerCase().replace(/^[a-z][a-z0-9+.-]*:\/\//, "").replace(/[/?#].*$/, "").replace(/^[^@]*@/, "").replace(/:\d+$/, "").replace(/^\*\./, "").replace(/\.$/, "");
  return /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(h) ? h : "";
}

function readForm(slot) {
  const $ = (s) => slot.querySelector(s);
  const chUrl = ($("#mfChUrl").value || "").trim();
  const chType = $("#mfChType").value;
  const chSecret = ($("#mfChSecret").value || "").trim();
  const channels = chUrl ? [{ type: chType, url: chUrl, ...(chType === "webhook" && chSecret ? { secret: chSecret } : {}) }] : [];
  const intervalMs = Math.max(15, Math.min(10080, Number($("#mfInt").value) || 1440)) * 60000;
  if (S.kind === "kev-epss") {
    // an empty field is Number("") = 0, which would alert on every CVE with any EPSS score
    const floorEl = $("#mfEpss"), floorTxt = floorEl ? floorEl.value.trim() : "", floorRaw = floorTxt ? Number(floorTxt) : NaN;
    const epssFloor = Number.isFinite(floorRaw) ? Math.max(0, Math.min(1, floorRaw)) : 0.5;
    return { name: ($("#mfName").value || "").trim() || "KEV / EPSS watch", type: "kev-epss", config: { epssFloor }, intervalMs, channels };
  }
  // A pasted URL ("https://site.com/path"), host:port or *.wildcard is reduced to its hostname;
  // the CT lookup finds nothing for anything else and the monitor would sit at "0 open".
  const raw = ($("#mfDomains").value || "").split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);
  const domains = [], bad = [];
  for (const x of raw) { const h = hostOf(x); if (h) { if (!domains.includes(h)) domains.push(h); } else bad.push(x); }
  return {
    bad,
    name: ($("#mfName").value || "").trim() || "Certificate monitor",
    type: "cert-expiry",
    config: { domains, warnDays: Math.max(1, Math.min(365, Number($("#mfWarn").value) || 21)) },
    intervalMs,
    channels,
  };
}

async function saveMonitor(slot) {
  if (S.busy) return;
  const mon = readForm(slot);
  if (mon.bad && mon.bad.length) { toast("Not a domain name: " + mon.bad.slice(0, 3).join(", ") + (mon.bad.length > 3 ? " and " + (mon.bad.length - 3) + " more" : "") + ". Use hostnames such as test.darknode.ai.", "warn"); return; }
  delete mon.bad;
  if (mon.type === "cert-expiry" && !mon.config.domains.length) { toast("Add at least one domain.", "warn"); return; }
  S.busy = true;
  try { await monitorApi({ op: "upsert", monitor: mon }); toast("Monitor saved.", "ok"); S.adding = false; await load(); }
  catch (e) { toast(e.message || "Could not save.", "error"); }
  finally { S.busy = false; }
}

async function testChannel(slot) {
  const mon = readForm(slot);
  if (!mon.channels.length) { toast("Add a channel URL to test.", "warn"); return; }
  const deckUrl = location.origin + location.pathname + "#monitors";
  try { const r = await monitorApi({ op: "test", channel: mon.channels[0], deckUrl }); toast(r.ok ? "Test alert sent." : "Delivery failed" + (r.error ? ": " + r.error : r.status ? " (HTTP " + r.status + ")" : "") + ". Check the URL.", r.ok ? "ok" : "error"); }
  catch (e) { toast(e.message || "Test failed.", "error"); }
}

async function act_run(id) {
  toast("Running monitor…");
  try { await monitorApi({ op: "run", id, deckUrl: location.origin + location.pathname + "#monitors" }); await load(); toast("Run complete.", "ok"); }
  catch (e) { toast(e.message || "Run failed.", "error"); }
}
async function act_pause(id, row) {
  // Toggle against the authoritative record, not rendered markup — reading row.innerHTML
  // inverted the state for any markup change or a monitor whose text contained "Paused".
  const mon = ((S.data && S.data.monitors) || []).find((m) => m.id === id);
  const paused = !(mon && mon.paused);
  try { await monitorApi({ op: "pause", id, paused }); await load(); }
  catch (e) { toast(e.message || "Could not update.", "error"); }
}
async function act_del(id, row) {
  const name = (row.querySelector(".mon-name") || {}).textContent || "this monitor";
  // Fail closed: if the confirm modal is unavailable, do NOT delete (the old `: true`
  // fallback deleted with no confirmation). No native dialogs per the UI rules.
  if (!window.dnConfirm) { toast("Confirmation unavailable — monitor not deleted.", "error"); return; }
  const ok = await window.dnConfirm("Delete " + name + "? This stops its scheduled checks.");
  if (!ok) return;
  try { await monitorApi({ op: "delete", id }); await load(); toast("Monitor deleted.", "ok"); }
  catch (e) { toast(e.message || "Could not delete.", "error"); }
}
