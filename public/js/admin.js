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
      <div class="stat"><div class="stat-n" id="stNew">…</div><div class="stat-l">new this week</div></div>
      <div class="stat"><div class="stat-n" id="stActive">…</div><div class="stat-l">active today</div></div>
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
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Feedback &amp; bug reports</h2>
            <button class="btn ghost sm" id="fbRefresh">Refresh</button></div>
          <div id="fbAdminList"><p class="muted">Loading feedback…</p></div>
        </div>
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Data &amp; outreach</h2></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 10px">Export the user base or grab every email for an announcement mailout.</p>
          <div class="set-btns">
            <button class="btn sm" id="expCsv">Export users (CSV)</button>
            <button class="btn ghost sm" id="copyEmails">Copy all emails</button>
            <button class="btn ghost sm" id="copyOwnerless">Copy non-owner emails</button>
          </div>
          <p class="adm-msg" id="dataMsg"></p>
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
          <div class="row" id="annPresets" style="gap:6px;flex-wrap:wrap;margin-bottom:8px">
            <button class="btn ghost sm" data-preset="maint">Maintenance</button>
            <button class="btn ghost sm" data-preset="release">New release</button>
            <button class="btn ghost sm" data-preset="security">Security notice</button>
          </div>
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
      const toMs = (ts) => ts && ts.toMillis ? ts.toMillis() : (ts && ts.toDate ? ts.toDate().getTime() : (typeof ts === "number" ? (ts < 1e12 ? ts * 1000 : ts) : 0));
      const now = Date.now(), day = 864e5, midnight = new Date(); midnight.setHours(0, 0, 0, 0);
      $("#stNew").textContent = users.filter((u) => { const c = toMs(u.created || u.createdAt); return c && now - c < 7 * day; }).length || "—";
      $("#stActive").textContent = users.filter((u) => toMs(u.lastSeen) >= midnight.getTime()).length;
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

  // ---- feedback / bug reports ----
  async function loadFeedback() {
    const host = $("#fbAdminList"); if (!host) return;
    try {
      const snap = await getDocs(collection(db, "feedback"));
      const toMs = (ts) => (ts && ts.toMillis ? ts.toMillis() : 0);
      const items = snap.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => toMs(b.ts) - toMs(a.ts));
      if (!items.length) { host.innerHTML = `<p class="muted">No feedback yet.</p>`; return; }
      const icon = { bug: "🐞", feedback: "💬", idea: "💡" };
      host.innerHTML = items.map((f) => `
        <div class="fb-row" data-id="${esc(f.id)}">
          <div class="fb-row-h"><span class="fb-tag">${icon[f.type] || "•"} ${esc(f.type || "note")}</span> <span class="muted">${esc(f.email || "anon")}</span><span style="flex:1"></span><span class="muted" style="font-size:.72rem">${f.ts && f.ts.toDate ? esc(fmtDate(f.ts)) : ""}</span><button class="btn ghost sm fb-del" title="Delete">✕</button></div>
          <div class="fb-msg">${esc(f.message || "")}</div>
          ${f.url ? `<div class="muted" style="font-size:.7rem;margin-top:4px">${esc(f.url)}</div>` : ""}
        </div>`).join("");
    } catch (e) { host.innerHTML = `<p class="adm-err">Couldn't load feedback: ${esc(e.message)}. Ensure Firestore rules allow the owner to read the 'feedback' collection.</p>`; }
  }
  $("#fbRefresh").onclick = loadFeedback;
  $("#fbAdminList").onclick = async (e) => {
    const del = e.target.closest(".fb-del"); if (!del) return;
    const row = del.closest(".fb-row"); if (!row) return;
    if (!confirm("Delete this feedback?")) return;
    try { await deleteDoc(doc(db, "feedback", row.dataset.id)); row.remove(); } catch (err) { alert("delete failed: " + err.message); }
  };
  loadFeedback();
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

  // ---- announcement presets ----
  const PRESETS = {
    maint: "Scheduled maintenance is underway — some features may be briefly unavailable. Thanks for your patience.",
    release: "New release is live! Update the desktop app and CLI from the Downloads page to get the latest tools and fixes.",
    security: "Security notice: rotate any credentials you've stored and review recent sign-ins. Contact the owner with questions.",
  };
  $("#annPresets").onclick = (e) => { const b = e.target.closest("[data-preset]"); if (!b) return; $("#annText").value = PRESETS[b.dataset.preset] || ""; annType = b.dataset.preset === "security" ? "warn" : "info"; $("#annType").querySelectorAll("button").forEach((x) => x.classList.toggle("on", x.dataset.v === annType)); };

  // ---- data & outreach ----
  const dmsg = (t) => { const m = $("#dataMsg"); m.className = "adm-msg ok"; m.textContent = t; setTimeout(() => (m.textContent = ""), 2000); };
  const emailsOf = (list) => list.map((u) => u.email).filter(Boolean).join(", ");
  $("#copyEmails").onclick = () => { navigator.clipboard?.writeText(emailsOf(users)); dmsg(users.filter((u) => u.email).length + " emails copied"); };
  $("#copyOwnerless").onclick = () => { const l = users.filter((u) => u.email !== OWNER_EMAIL); navigator.clipboard?.writeText(emailsOf(l)); dmsg(l.filter((u) => u.email).length + " emails copied"); };
  $("#expCsv").onclick = () => {
    const esc2 = (v) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const rows = [["email", "name", "uid", "lastSeen", "allow-listed"]].concat(users.map((u) => [u.email, u.name, u.uid, fmtDate(u.lastSeen), wl.emails.includes((u.email || "").toLowerCase()) ? "yes" : "no"]));
    const csv = rows.map((r) => r.map(esc2).join(",")).join("\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    const a = document.createElement("a"); a.href = url; a.download = "sentinel-users.csv"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    dmsg("exported " + users.length + " users");
  };

  await Promise.all([loadWl(), loadUsers(), loadAnn()]);
}
