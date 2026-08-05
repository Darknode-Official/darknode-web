// Owner-only admin console: live user management, an allow-list (with sign-in
// enforcement), and site-wide announcements. All backed by Firestore.
import { db, OWNER_EMAIL } from "/js/firebase.js";
import {
  collection, getDocs, doc, getDoc, setDoc, deleteDoc, serverTimestamp,
} from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtDate = (ts) => {
  try { const d = ts?.toDate ? ts.toDate() : (ts ? new Date(ts) : null); return d ? d.toLocaleString() : "—"; } catch (_) { return "—"; }
};

const WL_REF = () => doc(db, "settings", "whitelist");
const ANN_REF = () => doc(db, "announcements", "current");

// Read the whitelist doc; used by auth.js for sign-in enforcement too.
export async function getWhitelist() {
  try { const s = await getDoc(WL_REF()); return s.exists() ? s.data() : { emails: [], enforce: false }; }
  catch (_) { return { emails: [], enforce: false }; }
}

export async function renderAdmin(main, user) {
  main.innerHTML = `
    <h1 class="pg-h1">Admin</h1>
    <p class="muted pg-sub">Owner console &mdash; ${esc(user.email)} <span class="owner-badge">OWNER</span></p>

    <div class="stat-row" id="admStats">
      <div class="stat"><div class="stat-n" id="stUsers">…</div><div class="stat-l">users</div></div>
      <div class="stat"><div class="stat-n" id="stWl">…</div><div class="stat-l">allow-listed</div></div>
      <div class="stat"><div class="stat-n" id="stAnn">…</div><div class="stat-l">announcement</div></div>
    </div>

    <div class="adm-cols">
      <div class="adm-main">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Users</h2>
            <button class="btn ghost sm" id="uRefresh">Refresh</button></div>
          <input class="tk-search" id="uSearch" placeholder="Search by email or name…">
          <div id="uList"><p class="muted">Loading users…</p></div>
        </div>
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Recent new-device sign-ins</h2></div>
          <div id="loginList"><p class="muted">…</p></div>
        </div>
      </div>
      <div class="adm-side">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Allow-list</h2></div>
          <label class="set-row" style="border:none;padding:4px 0">
            <span class="muted">Restrict sign-in to allow-listed emails</span>
            <input type="checkbox" id="wlEnforce" style="width:18px;height:18px;accent-color:var(--acc)">
          </label>
          <div class="row" style="margin:6px 0 10px">
            <input class="tk-f" id="wlEmail" placeholder="name@example.com" type="email">
            <button class="btn sm" id="wlAdd">Add</button>
          </div>
          <div class="wl-list" id="wlList"></div>
          <p class="muted" style="font-size:.72rem;margin:10px 0 0">The owner (${esc(OWNER_EMAIL)}) always has access.</p>
        </div>

        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Announcement</h2></div>
          <textarea class="tk-in" id="annText" rows="3" placeholder="Message shown to everyone at the top of the site…"></textarea>
          <div class="row" style="margin:8px 0">
            <span class="seg" id="annType"><button data-v="info" class="on">Info</button><button data-v="warn">Warning</button></span>
            <label class="muted" style="display:flex;gap:6px;align-items:center;font-size:.82rem">
              <input type="checkbox" id="annActive" style="width:16px;height:16px;accent-color:var(--acc)"> Active</label>
          </div>
          <div class="set-btns">
            <button class="btn sm" id="annPublish">Publish</button>
            <button class="btn ghost sm" id="annClear">Clear banner</button>
          </div>
          <p class="adm-msg" id="annMsg"></p>
        </div>
      </div>
    </div>`;

  const $ = (id) => main.querySelector(id);
  let users = [];
  let wl = { emails: [], enforce: false };

  // ---- users ----
  async function loadUsers() {
    const host = $("#uList");
    try {
      const snap = await getDocs(collection(db, "users"));
      users = snap.docs.map((d) => ({ uid: d.id, ...d.data() }));
      $("#stUsers").textContent = users.length;
      drawUsers();
      const alerts = [];
      users.forEach((u) => (u.logins || []).forEach((l) => alerts.push({ email: u.email, device: l.device, ts: l.ts })));
      alerts.sort((a, b) => (b.ts || 0) - (a.ts || 0));
      $("#loginList").innerHTML = alerts.length
        ? alerts.slice(0, 20).map((a) => `<div class="user-row"><div class="ur-main"><div class="ur-name">${esc(a.device || "device")}</div><div class="ur-mail muted">${esc(a.email || "")}</div></div><div class="ur-seen muted">${esc(fmtDate(a.ts))}</div></div>`).join("")
        : `<p class="muted" style="font-size:.82rem">No new-device sign-ins recorded yet.</p>`;
    } catch (e) {
      host.innerHTML = `<p class="adm-err">Couldn't load users: ${esc(e.message)}. Make sure Firestore rules are deployed.</p>`;
      $("#stUsers").textContent = "—";
    }
  }
  function drawUsers() {
    const q = ($("#uSearch").value || "").toLowerCase().trim();
    const rows = users
      .filter((u) => !q || (u.email + " " + (u.name || "")).toLowerCase().includes(q))
      .sort((a, b) => (a.email || "").localeCompare(b.email || ""));
    const host = $("#uList");
    if (!rows.length) { host.innerHTML = `<p class="muted">No matching users.</p>`; return; }
    host.innerHTML = rows.map((u) => {
      const isOwner = u.email === OWNER_EMAIL;
      const listed = wl.emails.includes((u.email || "").toLowerCase());
      return `<div class="user-row">
        <div class="ur-main">
          <div class="ur-name">${esc(u.name || "(no name)")} ${isOwner ? '<span class="owner-badge">OWNER</span>' : ""}${listed ? '<span class="chip">allow-listed</span>' : ""}</div>
          <div class="ur-mail muted">${esc(u.email || u.uid)}</div>
          <div class="ur-seen muted">last seen ${esc(fmtDate(u.lastSeen))}</div>
        </div>
        <div class="ur-actions">
          <button class="btn ghost sm" data-wl="${esc(u.email || "")}">${listed ? "Un-list" : "Allow-list"}</button>
          ${isOwner ? "" : `<button class="btn danger sm" data-del="${esc(u.uid)}" data-mail="${esc(u.email || "")}">Remove</button>`}
        </div>
      </div>`;
    }).join("");
  }
  $("#uRefresh").onclick = loadUsers;
  $("#uSearch").oninput = drawUsers;
  $("#uList").onclick = async (e) => {
    const wlBtn = e.target.closest("[data-wl]"), delBtn = e.target.closest("[data-del]");
    if (wlBtn) { await toggleWl(wlBtn.dataset.wl); }
    else if (delBtn) {
      if (!confirm(`Remove ${delBtn.dataset.mail || "this user"}? This deletes their Firestore record.`)) return;
      try { await deleteDoc(doc(db, "users", delBtn.dataset.del)); users = users.filter((u) => u.uid !== delBtn.dataset.del); $("#stUsers").textContent = users.length; drawUsers(); }
      catch (err) { alert("Delete failed: " + err.message); }
    }
  };

  // ---- whitelist ----
  async function loadWl() {
    wl = await getWhitelist();
    wl.emails = (wl.emails || []).map((x) => x.toLowerCase());
    $("#wlEnforce").checked = !!wl.enforce;
    $("#stWl").textContent = wl.emails.length;
    drawWl();
  }
  function drawWl() {
    const host = $("#wlList");
    host.innerHTML = wl.emails.length
      ? wl.emails.map((em) => `<div class="wl-item"><span class="mono">${esc(em)}</span><button class="wl-x" data-rm="${esc(em)}" title="remove">&times;</button></div>`).join("")
      : `<p class="muted" style="font-size:.8rem">No emails yet. Add one above.</p>`;
  }
  async function saveWl() {
    try {
      await setDoc(WL_REF(), { emails: wl.emails, enforce: $("#wlEnforce").checked, updatedBy: user.email, updatedAt: serverTimestamp() }, { merge: true });
      $("#stWl").textContent = wl.emails.length;
      return true;
    } catch (e) { alert("Couldn't save allow-list: " + e.message); return false; }
  }
  async function toggleWl(email) {
    email = (email || "").toLowerCase().trim(); if (!email) return;
    if (wl.emails.includes(email)) wl.emails = wl.emails.filter((x) => x !== email);
    else wl.emails.push(email);
    if (await saveWl()) { drawWl(); drawUsers(); }
  }
  $("#wlAdd").onclick = async () => { const v = $("#wlEmail").value.trim(); if (v) { await toggleWl(v); $("#wlEmail").value = ""; } };
  $("#wlEmail").onkeydown = (e) => { if (e.key === "Enter") $("#wlAdd").click(); };
  $("#wlList").onclick = (e) => { const b = e.target.closest("[data-rm]"); if (b) toggleWl(b.dataset.rm); };
  $("#wlEnforce").onchange = saveWl;

  // ---- announcement ----
  let annType = "info";
  $("#annType").onclick = (e) => { const b = e.target.closest("button[data-v]"); if (!b) return; annType = b.dataset.v; $("#annType").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x === b)); };
  async function loadAnn() {
    try {
      const s = await getDoc(ANN_REF());
      if (s.exists()) {
        const d = s.data();
        $("#annText").value = d.text || "";
        $("#annActive").checked = !!d.active;
        annType = d.type === "warn" ? "warn" : "info";
        $("#annType").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x.dataset.v === annType));
        $("#stAnn").textContent = d.active ? "live" : "off";
      } else { $("#stAnn").textContent = "off"; }
    } catch (_) { $("#stAnn").textContent = "—"; }
  }
  async function publishAnn(active) {
    const msg = $("#annMsg"), text = $("#annText").value.trim();
    try {
      await setDoc(ANN_REF(), { text, type: annType, active, updatedBy: user.email, updatedAt: serverTimestamp() }, { merge: true });
      $("#annActive").checked = active;
      $("#stAnn").textContent = active ? "live" : "off";
      // update the live banner in this session immediately
      const el = document.getElementById("announcement");
      if (el) { if (active && text) { el.textContent = text; el.classList.toggle("banner-info", annType !== "warn"); el.hidden = false; } else { el.hidden = true; } }
      msg.className = "adm-msg ok"; msg.textContent = active ? "Published — visible to everyone." : "Banner cleared.";
      setTimeout(() => (msg.textContent = ""), 2500);
    } catch (e) { msg.className = "adm-msg err"; msg.textContent = "Failed: " + e.message; }
  }
  $("#annPublish").onclick = () => {
    if (!$("#annText").value.trim()) { const m = $("#annMsg"); m.className = "adm-msg err"; m.textContent = "write a message first"; return; }
    $("#annActive").checked = true; publishAnn(true);
  };
  $("#annClear").onclick = () => publishAnn(false);

  await Promise.all([loadWl(), loadUsers(), loadAnn()]);
}
