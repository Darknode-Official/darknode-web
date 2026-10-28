// API & Ingest scene (Deck D5): issue workspace API keys and push findings in from CI.
// A key is shown once; only its hash is stored server-side. Findings sent to the ingest
// endpoint queue on the server and are pulled into the Security Graph here, through the
// same sink every tool uses.
import { ingestAvailable, ingestBaseUrl, ingestWorkspaceId, listKeys, createKey, revokeKey, peekQueue, drainIngest } from "/js/deck/ingest-client.js?v=20261027c";

const S = { ctx: null, el: null, data: null, wid: "", busy: false, created: null };
const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const toast = (m, t) => { try { S.ctx && S.ctx.toast && S.ctx.toast(m, t); } catch (_) {} };
const ago = (ts) => { if (!ts) return "never"; const s = Math.floor((Date.now() - ts) / 1000); if (s < 60) return "just now"; if (s < 3600) return Math.floor(s / 60) + "m ago"; if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago"; };

function injectStyle() {
  if (document.getElementById("apik-css")) return;
  const st = document.createElement("style"); st.id = "apik-css";
  st.textContent = `
.apik-sub{color:#5a6680;font-size:12.5px;margin:-2px 0 14px;line-height:1.5}
.apik-row{display:flex;align-items:center;gap:10px;border:1px solid rgba(23,33,56,.12);border-radius:9px;padding:10px 13px;margin:0 0 8px;flex-wrap:wrap}
.apik-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:#141c2e;background:rgba(23,33,56,.05);border-radius:6px;padding:2px 7px}
.apik-scope{font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 8px;background:rgba(37,82,198,.1);color:#2552c6}
.apik-rev{font-size:10.5px;font-weight:700;border-radius:20px;padding:1px 8px;background:rgba(198,40,40,.1);color:#c62828}
.apik-meta{color:#5a6680;font-size:12px;margin-left:auto}
.apik-btn{appearance:none;border:1px solid rgba(23,33,56,.16);background:#fff;border-radius:7px;font:inherit;font-size:12px;font-weight:600;color:#2a3450;padding:4px 10px;cursor:pointer}
.apik-btn:hover{border-color:var(--dk-acc,#2552c6);color:var(--dk-acc,#2552c6)}
.apik-btn.danger:hover{border-color:#c62828;color:#c62828}
.apik-btn.pri{background:var(--dk-acc,#2552c6);border-color:var(--dk-acc,#2552c6);color:#fff}
.apik-new{border:1px solid rgba(18,168,95,.4);background:rgba(18,168,95,.06);border-radius:10px;padding:13px 15px;margin:0 0 16px}
.apik-new h3{margin:0 0 6px;font-size:13.5px}
.apik-keybox{display:flex;gap:8px;align-items:center;margin:8px 0 4px}
.apik-keybox input{flex:1;font-family:ui-monospace,monospace;font-size:12.5px;border:1px solid rgba(23,33,56,.2);border-radius:7px;padding:7px 9px}
.apik-warn{font-size:12px;color:#7a4a00}
.apik-form{border:1px dashed rgba(37,82,198,.4);border-radius:10px;padding:14px;margin:0 0 16px;background:rgba(37,82,198,.03)}
.apik-field{margin:0 0 10px}.apik-field label{display:block;font-size:12px;font-weight:600;color:#2a3450;margin:0 0 3px}
.apik-field input[type=text]{width:100%;max-width:360px;font:inherit;font-size:13px;border:1px solid rgba(23,33,56,.18);border-radius:7px;padding:7px 9px;box-sizing:border-box}
.apik-chk{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;margin-right:16px}
.apik-panel{margin:20px 0 0}.apik-panel h2{font-size:14px;margin:0 0 7px}
.apik-pre{font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.55;background:#0f1522;color:#d6def0;border-radius:9px;padding:12px 14px;overflow-x:auto;white-space:pre}
.apik-off{font-size:12.5px;color:#7a4a00;background:rgba(245,146,11,.1);border-radius:8px;padding:11px 13px;line-height:1.5}
`;
  document.head.appendChild(st);
}

export function mountApiKeys(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el; S.created = null;
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>API &amp; Ingest</h1><p>Issue a workspace API key and push findings in from CI — SARIF, CycloneDX, the Finding JSON contract, or a native scanner export (Nessus, Qualys, OpenVAS, Trivy, Grype, Snyk, Rapid7, Defender). Keys are shown once and stored only as a hash. Ingested findings land in your Security Graph exactly like a tool's own results.</p></div></div>
    <div class="dk-ovp" id="apikBody"><div class="dk-loading"><span class="sp"></span>Loading…</div></div>`;
  load();
}
export function repaintApiKeys() {}

async function load() {
  const box = S.el && S.el.querySelector("#apikBody"); if (!box) return;
  if (!ingestAvailable()) { box.innerHTML = `<div class="apik-off">The ingest API is not available on this build — it needs the cloud proxy. Nothing to configure yet.</div>`; return; }
  try {
    S.wid = await ingestWorkspaceId();
    S.data = await listKeys();
    let q = { pending: 0 }; try { q = await peekQueue(); } catch (_) {}
    S.pending = q.pending || 0;
    paint();
  } catch (e) { box.innerHTML = `<div class="apik-off">${E(e.message || String(e))}</div>`; }
}

function paint() {
  const box = S.el && S.el.querySelector("#apikBody"); if (!box || !S.data) return;
  const keys = (S.data.keys || []).filter((k) => !k.revoked);
  const base = ingestBaseUrl();
  const wid = S.wid || "<workspace-id>";
  const keyHtml = keys.length ? keys.map((k) => `<div class="apik-row" data-id="${E(k.keyId)}">
      <span class="apik-code">${E(k.prefix)}</span>
      ${(k.scopes || []).map((s) => `<span class="apik-scope">${E(s)}</span>`).join("")}
      <span class="apik-meta">${E(k.label)} · created ${E(ago(k.createdAt))} · used ${E(ago(k.lastUsedAt))}</span>
      <button class="apik-btn danger" data-act="revoke">Revoke</button>
    </div>`).join("") : `<div class="dk-nempty">No API keys yet. Create one to push findings in from a pipeline.</div>`;

  const curl = `curl -X POST "${base}/api/v1/ingest/${wid}" \\
  -H "x-darknode-key: $DARKNODE_KEY" \\
  -H "content-type: application/json" \\
  --data-binary @results.sarif`;
  const gha = `- name: Push findings to Darknode
  run: |
    curl -X POST "${base}/api/v1/ingest/${wid}" \\
      -H "x-darknode-key: \${{ secrets.DARKNODE_KEY }}" \\
      -H "content-type: application/json" \\
      --data-binary @results.sarif`;

  box.innerHTML = `
    ${S.created ? newKeyPanel(S.created) : ""}
    <div style="display:flex;gap:8px;margin:0 0 14px;flex-wrap:wrap">
      <button class="apik-btn pri" id="apikNew">Create API key</button>
      <button class="apik-btn" id="apikDrain">Pull ingested findings${S.pending ? ` (${S.pending} pending)` : ""}</button>
    </div>
    <div id="apikFormSlot"></div>
    <h2 style="font-size:14px;margin:0 0 7px">Keys</h2>
    ${keyHtml}
    <div class="apik-panel"><h2>Push findings from CI</h2>
      <p class="apik-sub">POST SARIF, CycloneDX, the Finding JSON contract, or a scanner export (Nessus, Trivy, Snyk and others) to the ingest endpoint with your key. The Deck pulls them in when you open it; or click “Pull ingested findings” to sync now.</p>
      <div class="apik-pre">${E(curl)}</div>
      <h2 style="font-size:13px;margin:14px 0 6px">GitHub Actions step</h2>
      <div class="apik-pre">${E(gha)}</div>
    </div>`;

  box.querySelector("#apikNew").onclick = () => renderForm(true);
  box.querySelector("#apikDrain").onclick = drain;
  box.querySelectorAll(".apik-row").forEach((row) => { const b = row.querySelector('[data-act="revoke"]'); if (b) b.onclick = () => doRevoke(row.dataset.id, row); });
  if (S.created) { const inp = box.querySelector("#apikKeyVal"); if (inp) { const cp = box.querySelector("#apikCopy"); if (cp) cp.onclick = async () => { inp.select(); try { await navigator.clipboard.writeText(inp.value); toast("Key copied.", "ok"); } catch (_) { toast("Could not copy - the key is selected; press Ctrl+C (Cmd+C) to copy it.", "warn"); } }; } }
}

function newKeyPanel(c) {
  return `<div class="apik-new"><h3>Your new API key</h3>
    <div class="apik-keybox"><input id="apikKeyVal" aria-label="New API key" readonly value="${E(c.key)}"><button class="apik-btn" id="apikCopy">Copy</button></div>
    <p class="apik-warn">Copy it now — it is shown once and cannot be retrieved again. Store it as a CI secret (e.g. DARKNODE_KEY).</p></div>`;
}

function renderForm(open) {
  const slot = S.el && S.el.querySelector("#apikFormSlot"); if (!slot) return;
  if (!open) { slot.innerHTML = ""; return; }
  slot.innerHTML = `<div class="apik-form">
    <div class="apik-field"><label for="afLabel">Label</label><input type="text" id="afLabel" placeholder="CI pipeline" autocomplete="off"></div>
    <div class="apik-field"><label>Scopes</label>
      <label class="apik-chk"><input type="checkbox" id="afIngest" checked> Ingest findings (ingest:write)</label>
      <label class="apik-chk"><input type="checkbox" id="afRead"> Read findings back (findings:read)</label>
    </div>
    <div style="display:flex;gap:8px"><button class="apik-btn pri" id="afSave">Create key</button><button class="apik-btn" id="afCancel">Cancel</button></div>
  </div>`;
  slot.querySelector("#afCancel").onclick = () => renderForm(false);
  slot.querySelector("#afSave").onclick = () => doCreate(slot);
}

async function doCreate(slot) {
  if (S.busy) return;
  const label = (slot.querySelector("#afLabel").value || "").trim() || "API key";
  const scopes = [];
  if (slot.querySelector("#afIngest").checked) scopes.push("ingest:write");
  if (slot.querySelector("#afRead").checked) scopes.push("findings:read");
  if (!scopes.length) { toast("Pick at least one scope.", "warn"); return; } // the server would otherwise grant ingest:write
  S.busy = true;
  try { const r = await createKey(label, scopes); S.created = r; await load(); toast("API key created.", "ok"); }
  catch (e) { toast(e.message || "Could not create key.", "error"); }
  finally { S.busy = false; }
}

async function doRevoke(keyId, row) {
  if (!window.dnConfirm) { toast("Confirmation unavailable — key not revoked.", "error"); return; } // fail closed, as Monitors does
  const ok = await window.dnConfirm("Revoke this API key? Any pipeline using it will stop working.");
  if (!ok) return;
  try { await revokeKey(keyId); await load(); toast("Key revoked.", "ok"); }
  catch (e) { toast(e.message || "Could not revoke.", "error"); }
}

async function drain() {
  toast("Pulling ingested findings…");
  try {
    const r = await drainIngest();
    if (!r.batches) toast("No pending findings to pull.", "ok");
    else toast(`Pulled ${r.batches} batch${r.batches === 1 ? "" : "es"}: ${r.created} added, ${r.updated} updated.` + (r.failed ? ` ${r.failed} could not be added to the graph; send ${r.failed === 1 ? "it" : "them"} again.` : ""), r.failed ? "error" : "ok");
    await load();
  } catch (e) { toast(e.message || "Pull failed.", "error"); }
}
