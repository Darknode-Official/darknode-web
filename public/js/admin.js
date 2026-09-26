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
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Client Error Log</h2>
            <button class="btn ghost sm" id="errRefresh">Refresh</button>
            <button class="btn danger sm" id="errClear">Clear all</button></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 8px">Automatic crash reports from user sessions.</p>
          <div id="errAdminList"><p class="muted">Loading errors…</p></div>
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
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Email Users</h2></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 10px">Send an email from contact@darknode.ai to one user or all registered users.</p>
          <div style="margin-bottom:10px">
            <label class="set-row" style="border:none;padding:4px 18px;gap:12px">
              <span class="seg" id="emailTarget">
                <button data-v="one" class="on">One user</button>
                <button data-v="all">All users</button>
              </span>
            </label>
          </div>
          <div id="emailOneRow" style="margin-bottom:8px">
            <input class="tk-f" id="emailTo" placeholder="user@example.com" type="email" style="width:100%">
          </div>
          <input class="tk-f" id="emailSubject" placeholder="Subject" style="width:100%;margin-bottom:8px">
          <textarea class="tk-in" id="emailBody" rows="6" placeholder="Write your message here..."></textarea>
          <div style="display:flex;gap:8px;margin-top:8px;align-items:center">
            <button class="btn sm" id="emailSend">Open in Gmail</button>
            <button class="btn ghost sm" id="emailCopyDraft">Copy as text</button>
            <span class="muted" style="font-size:.72rem;flex:1;text-align:right" id="emailCount"></span>
          </div>
          <p class="adm-msg" id="emailMsg"></p>
          <div style="margin-top:10px;border-top:1px solid var(--line);padding-top:10px">
            <p class="muted" style="font-size:.75rem;margin:0 0 6px">Quick templates:</p>
            <div class="btn-grid">
              <button class="btn ghost sm emailTpl" data-tpl="downtime">Downtime apology</button>
              <button class="btn ghost sm emailTpl" data-tpl="update">New update</button>
              <button class="btn ghost sm emailTpl" data-tpl="welcome">Welcome</button>
              <button class="btn ghost sm emailTpl" data-tpl="security">Security notice</button>
            </div>
          </div>
        </div>
      </div>
      <div class="adm-side">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Allow-list</h2></div>
          <label class="set-row" style="border:none;padding:4px 18px">
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
          <div class="btn-grid" id="annPresets" style="margin-bottom:8px">
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
    </div>

    <div class="panel" style="margin-top:16px">
      <div class="panel-h"><h2 class="pg-h2" style="margin:0">Site Analytics</h2>
        <button class="btn ghost sm" id="anaRefresh">Refresh</button></div>
      <div class="stat-row" id="anaStats">
        <div class="stat"><div class="stat-n" id="anaTotalTopics">--</div><div class="stat-l">Learn Hub topics</div></div>
        <div class="stat"><div class="stat-n" id="anaTopLearner">--</div><div class="stat-l">top learner</div></div>
        <div class="stat"><div class="stat-n" id="anaAvgXP">--</div><div class="stat-l">avg XP/user</div></div>
        <div class="stat"><div class="stat-n" id="anaCompletions">--</div><div class="stat-l">total completions</div></div>
      </div>
      <div id="anaChart" style="margin-top:12px"></div>
    </div>

    <div class="adm-cols" style="margin-top:16px">
      <div class="adm-main">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">User Activity Log</h2></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 8px">Recent user actions — sign-ins, page views, and tool usage.</p>
          <div id="actLog"><p class="muted">Loading activity...</p></div>
        </div>

        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Maintenance</h2></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 10px">System health and maintenance actions.</p>
          <div class="set-btns" style="flex-wrap:wrap">
            <button class="btn sm" id="admClearInactive">Remove inactive users (90d+)</button>
            <button class="btn ghost sm" id="admExportFeedback">Export feedback (JSON)</button>
            <button class="btn ghost sm" id="admResetStats">Reset analytics cache</button>
          </div>
          <p class="adm-msg" id="maintMsg"></p>
        </div>

        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Feature Flags</h2></div>
          <p class="muted" style="font-size:.82rem;margin:0 0 10px">Toggle site features on/off without redeploying.</p>
          <div id="featureFlags">
            <label class="set-row"><span>Learn Hub</span><input type="checkbox" id="ffLearn" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
            <label class="set-row"><span>Web Shell</span><input type="checkbox" id="ffWebshell" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
            <label class="set-row"><span>VM Lab</span><input type="checkbox" id="ffVmlab" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
            <label class="set-row"><span>AI Assistant</span><input type="checkbox" id="ffAI" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
            <label class="set-row"><span>Gmail Integration</span><input type="checkbox" id="ffGmail" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
            <label class="set-row"><span>GitHub Integration</span><input type="checkbox" id="ffGithub" checked style="width:18px;height:18px;accent-color:var(--acc)"></label>
          </div>
          <button class="btn sm" id="ffSave" style="margin-top:8px">Save flags</button>
          <p class="adm-msg" id="ffMsg"></p>
        </div>
      </div>

      <div class="adm-side">
        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Quick Actions</h2></div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="btn sm" id="admMsgAll">Message all users</button>
            <button class="btn ghost sm" id="admBackup">Backup all data (JSON)</button>
            <button class="btn ghost sm" id="admViewLogs">View error log</button>
            <button class="btn ghost sm" id="admTestEmail">Send test announcement</button>
          </div>
        </div>

        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">System Status</h2></div>
          <div id="sysStatus">
            <div class="set-row"><span class="muted">Firebase</span><span id="sysFb" style="color:#3fb950">connected</span></div>
            <div class="set-row"><span class="muted">Firestore</span><span id="sysFs" style="color:#3fb950">connected</span></div>
            <div class="set-row"><span class="muted">Learn Hub</span><span id="sysLh">--</span></div>
            <div class="set-row"><span class="muted">Render deploy</span><span id="sysDeploy">--</span></div>
            <div class="set-row"><span class="muted">JS bundle</span><span id="sysBundle">--</span></div>
          </div>
        </div>

        <div class="panel">
          <div class="panel-h"><h2 class="pg-h2" style="margin:0">Danger Zone</h2></div>
          <div style="display:flex;flex-direction:column;gap:8px">
            <button class="btn danger sm" id="admPurgeData">Purge all user data</button>
            <button class="btn danger sm" id="admRevokeAll">Revoke all sessions</button>
          </div>
          <p class="adm-msg" id="dangerMsg" style="color:var(--bad)"></p>
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
      .filter((u) => !q || (u.email + " " + (u.name || "") + " " + (u.provider || "")).toLowerCase().includes(q))
      .sort((a, b) => (a.email || "").localeCompare(b.email || ""));
    const host = $("#uList");
    if (!rows.length) { host.innerHTML = `<p class="muted">No matching users.</p>`; return; }
    host.innerHTML = rows.map((u) => {
      const isOwner = u.email === OWNER_EMAIL;
      const listed = wl.emails.includes((u.email || "").toLowerCase());
      const prov = u.provider || "email";
      const provBadge = prov.includes("google") ? '<span class="ur-prov google">Google</span>'
        : prov.includes("github") ? '<span class="ur-prov github">GitHub</span>'
        : '<span class="ur-prov email">Email</span>';
      const avatar = u.photoURL
        ? `<img class="ur-avatar" src="${esc(u.photoURL)}" alt="" width="32" height="32">`
        : `<span class="ur-avatar ur-initials">${esc((u.email || "?")[0].toUpperCase())}</span>`;
      return `<div class="user-row" data-uid="${esc(u.uid)}">
        ${avatar}
        <div class="ur-main">
          <div class="ur-name">${esc(u.name || "(no name)")} ${provBadge}${isOwner ? '<span class="owner-badge">OWNER</span>' : ""}${listed ? '<span class="chip">allow-listed</span>' : ""}</div>
          <div class="ur-mail muted">${esc(u.email || u.uid)}</div>
          <div class="ur-meta muted">last seen ${esc(fmtDate(u.lastSeen))}${u.createdAt ? " · joined " + esc(fmtDate(u.createdAt)) : ""}</div>
        </div>
        <div class="ur-actions">
          <button class="btn ghost sm ur-detail-btn" data-detail="${esc(u.uid)}">Details</button>
          <button class="btn ghost sm" data-wl="${esc(u.email || "")}">${listed ? "Un-list" : "Allow-list"}</button>
          ${isOwner ? "" : `<button class="btn danger sm" data-del="${esc(u.uid)}" data-mail="${esc(u.email || "")}">Remove</button>`}
        </div>
      </div>
      <div class="ur-details" id="detail-${esc(u.uid)}" style="display:none">
        <div class="ur-detail-grid">
          <div class="urd-item"><span class="muted">UID</span><span class="mono">${esc(u.uid)}</span></div>
          <div class="urd-item"><span class="muted">Email</span><span>${esc(u.email || "—")}</span></div>
          <div class="urd-item"><span class="muted">Display name</span><span>${esc(u.name || "—")}</span></div>
          <div class="urd-item"><span class="muted">Sign-in method</span><span>${esc(prov)}</span></div>
          <div class="urd-item"><span class="muted">Account created</span><span>${esc(fmtDate(u.createdAt || u.created))}</span></div>
          <div class="urd-item"><span class="muted">Last sign-in</span><span>${esc(fmtDate(u.lastLoginAt))}</span></div>
          <div class="urd-item"><span class="muted">Last seen</span><span>${esc(fmtDate(u.lastSeen))}</span></div>
          <div class="urd-item"><span class="muted">Known devices</span><span>${(u.devices || []).length}</span></div>
          <div class="urd-item"><span class="muted">Learn XP</span><span>${u.learnXP || 0}</span></div>
          <div class="urd-item"><span class="muted">Topics completed</span><span>${(u.learnCompleted || []).length}</span></div>
          <div class="urd-item"><span class="muted">TOS accepted</span><span>${u.tosAccepted ? "Yes" : "No"}</span></div>
          <div class="urd-item"><span class="muted">Allow-listed</span><span>${listed ? "Yes" : "No"}</span></div>
        </div>
        ${(u.logins || []).length ? `<div style="margin-top:8px"><span class="muted" style="font-size:.72rem">Recent sign-ins:</span><div class="urd-logins">${(u.logins || []).slice(-5).reverse().map(l => `<div class="urd-login"><span>${esc(l.device || "unknown")}</span><span class="muted">${esc(fmtDate(l.ts))}</span></div>`).join("")}</div></div>` : ""}
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
      host.innerHTML = items.map((f) => `
        <div class="fb-row" data-id="${esc(f.id)}">
          <div class="fb-row-h"><span class="fb-tag">${esc((f.type || "note").toUpperCase())}</span> <span class="muted">${esc(f.email || "anon")}</span><span style="flex:1"></span><span class="muted" style="font-size:.72rem">${f.ts && f.ts.toDate ? esc(fmtDate(f.ts)) : ""}</span><button class="btn ghost sm fb-del" title="Delete">Delete</button></div>
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

  // ---- client error log ----
  async function loadErrors() {
    const host = $("#errAdminList"); if (!host) return;
    try {
      const snap = await getDocs(collection(db, "errors"));
      const toMs = (ts) => (ts && ts.toMillis ? ts.toMillis() : 0);
      const items = snap.docs.map((d) => ({ id: d.id, ...d.data() })).sort((a, b) => toMs(b.ts) - toMs(a.ts));
      if (!items.length) { host.innerHTML = `<p class="muted">No errors logged.</p>`; return; }
      host.innerHTML = items.slice(0, 50).map((e) => `
        <div class="fb-row" data-id="${esc(e.id)}">
          <div class="fb-row-h">
            <span class="fb-tag" style="background:color-mix(in srgb,var(--bad) 18%,transparent);color:var(--bad)">ERROR</span>
            <span class="muted">${esc(e.email || "anon")}</span>
            <span style="flex:1"></span>
            <span class="muted" style="font-size:.72rem">${e.ts && e.ts.toDate ? esc(fmtDate(e.ts)) : ""}</span>
            <button class="btn ghost sm fb-del" title="Delete">Delete</button>
          </div>
          <div class="fb-msg" style="font-family:var(--font-mono,monospace);font-size:.78rem">${esc(e.message || "")}</div>
          ${e.source && e.source !== "unhandledrejection" ? `<div class="muted" style="font-size:.7rem;margin-top:2px">${esc(e.source)}${e.line ? ':' + e.line : ''}${e.col ? ':' + e.col : ''}</div>` : ""}
          ${e.stack ? `<details style="margin-top:4px"><summary class="muted" style="font-size:.72rem;cursor:pointer">Stack trace</summary><pre style="font-size:.7rem;margin:4px 0 0;white-space:pre-wrap;word-break:break-all;color:var(--mut)">${esc(e.stack)}</pre></details>` : ""}
          ${e.url ? `<div class="muted" style="font-size:.7rem;margin-top:2px">${esc(e.url)}</div>` : ""}
          ${e.ua ? `<div class="muted" style="font-size:.65rem;margin-top:2px">${esc(e.ua)}</div>` : ""}
        </div>`).join("") + (items.length > 50 ? `<p class="muted" style="font-size:.78rem;margin-top:8px">Showing 50 of ${items.length} errors</p>` : "");
    } catch (e) { host.innerHTML = `<p class="adm-err">Couldn't load errors: ${esc(e.message)}</p>`; }
  }
  $("#errRefresh").onclick = loadErrors;
  $("#errAdminList").onclick = async (e) => {
    const del = e.target.closest(".fb-del"); if (!del) return;
    const row = del.closest(".fb-row"); if (!row) return;
    if (!confirm("Delete this error?")) return;
    try { await deleteDoc(doc(db, "errors", row.dataset.id)); row.remove(); } catch (err) { alert("delete failed: " + err.message); }
  };
  $("#errClear").onclick = async () => {
    if (!confirm("Clear all logged errors?")) return;
    try {
      const snap = await getDocs(collection(db, "errors"));
      for (const d of snap.docs) { try { await deleteDoc(doc(db, "errors", d.id)); } catch (_) {} }
    } catch (err) { alert("clear failed: " + err.message); }
    loadErrors();
  };
  loadErrors();

  $("#uSearch").oninput = drawUsers;
  $("#uList").onclick = async (e) => {
    const detailBtn = e.target.closest("[data-detail]");
    if (detailBtn) {
      const panel = main.querySelector("#detail-" + detailBtn.dataset.detail);
      if (panel) { panel.style.display = panel.style.display === "none" ? "" : "none"; detailBtn.textContent = panel.style.display === "none" ? "Details" : "Hide"; }
      return;
    }
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
    const a = document.createElement("a"); a.href = url; a.download = "darknode-users.csv"; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    dmsg("exported " + users.length + " users");
  };

  await Promise.all([loadWl(), loadUsers(), loadAnn()]);

  // ---- Analytics ----
  async function loadAnalytics() {
    try {
      let totalXP = 0, totalCompletions = 0, topUser = { email: '-', xp: 0 };
      users.forEach(u => {
        const xp = u.learnXP || 0;
        const completed = (u.learnCompleted || []).length;
        totalXP += xp;
        totalCompletions += completed;
        if (xp > topUser.xp) topUser = { email: u.email || '?', xp };
      });
      const avgXP = users.length ? Math.round(totalXP / users.length) : 0;
      const anaTotalTopics = $("#anaTotalTopics");
      if (anaTotalTopics) {
        try {
          const r = await fetch('/data/topics.json');
          const topics = await r.json();
          anaTotalTopics.textContent = topics.length;
        } catch(_) { anaTotalTopics.textContent = '?'; }
      }
      const anaTopLearner = $("#anaTopLearner");
      if (anaTopLearner) anaTopLearner.textContent = topUser.email ? topUser.email.split('@')[0] : '-';
      const anaAvgXP = $("#anaAvgXP");
      if (anaAvgXP) anaAvgXP.textContent = avgXP;
      const anaCompletions = $("#anaCompletions");
      if (anaCompletions) anaCompletions.textContent = totalCompletions;

      // Registration chart (last 7 days)
      const chart = $("#anaChart");
      if (chart) {
        const days = [];
        for (let i = 6; i >= 0; i--) {
          const d = new Date(Date.now() - i * 864e5);
          const label = d.toLocaleDateString('en', { weekday: 'short' });
          const dayStart = new Date(d); dayStart.setHours(0,0,0,0);
          const dayEnd = new Date(d); dayEnd.setHours(23,59,59,999);
          const toMs = (ts) => ts && ts.toMillis ? ts.toMillis() : (ts && ts.toDate ? ts.toDate().getTime() : 0);
          const count = users.filter(u => { const c = toMs(u.created || u.createdAt); return c >= dayStart.getTime() && c <= dayEnd.getTime(); }).length;
          days.push({ label, count });
        }
        const max = Math.max(...days.map(d => d.count), 1);
        chart.innerHTML = '<div style="font-size:.75rem;color:var(--mut);margin-bottom:8px">New users (last 7 days)</div>' +
          '<div style="display:flex;align-items:flex-end;gap:6px;height:80px">' +
          days.map(d => `<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px"><div style="width:100%;background:var(--accent,#58a6ff);border-radius:3px;height:${Math.max(4, (d.count/max)*60)}px;transition:height .3s"></div><span style="font-size:.65rem;color:var(--mut)">${d.label}</span></div>`).join('') +
          '</div>';
      }
    } catch(e) { console.error('Analytics error:', e); }
  }
  const anaRefresh = $("#anaRefresh");
  if (anaRefresh) anaRefresh.onclick = loadAnalytics;

  // ---- Activity log ----
  async function loadActivityLog() {
    const log = $("#actLog");
    if (!log) return;
    try {
      const activities = [];
      users.forEach(u => {
        if (u.lastSeen) activities.push({ email: u.email, action: 'active', ts: u.lastSeen });
        (u.logins || []).forEach(l => activities.push({ email: u.email, action: 'login from ' + (l.device || 'unknown'), ts: l.ts }));
      });
      activities.sort((a, b) => {
        const ta = a.ts && a.ts.toMillis ? a.ts.toMillis() : (a.ts || 0);
        const tb = b.ts && b.ts.toMillis ? b.ts.toMillis() : (b.ts || 0);
        return tb - ta;
      });
      log.innerHTML = activities.length
        ? activities.slice(0, 15).map(a => `<div class="user-row" style="padding:6px 18px"><div class="ur-main"><div class="ur-name" style="font-size:.82rem">${esc(a.email || '?')}</div><div class="ur-mail muted" style="font-size:.72rem">${esc(a.action)}</div></div><div class="ur-seen muted" style="font-size:.72rem">${fmtDate(a.ts)}</div></div>`).join('')
        : '<p class="muted" style="font-size:.82rem">No activity recorded.</p>';
    } catch(e) { log.innerHTML = '<p class="muted">Could not load activity log.</p>'; }
  }

  // ---- Maintenance ----
  const clearInactive = $("#admClearInactive");
  if (clearInactive) clearInactive.onclick = async () => {
    const msg = $("#maintMsg");
    const cutoff = Date.now() - 90 * 864e5;
    const toMs = (ts) => ts && ts.toMillis ? ts.toMillis() : (ts && ts.toDate ? ts.toDate().getTime() : 0);
    const inactive = users.filter(u => {
      const last = toMs(u.lastSeen) || toMs(u.created || u.createdAt);
      return last && last < cutoff && u.email !== (OWNER_EMAIL || '');
    });
    if (!inactive.length) { if (msg) msg.textContent = 'No inactive users found.'; return; }
    if (!confirm('Remove ' + inactive.length + ' users inactive for 90+ days?')) return;
    let removed = 0;
    for (const u of inactive) {
      try { await deleteDoc(doc(db, "users", u.uid)); removed++; } catch(_) {}
    }
    if (msg) msg.textContent = 'Removed ' + removed + ' inactive users.';
    loadUsers();
  };

  const exportFeedback = $("#admExportFeedback");
  if (exportFeedback) exportFeedback.onclick = async () => {
    try {
      const snap = await getDocs(collection(db, "feedback"));
      const data = snap.docs.map(d => ({ id: d.id, ...d.data() }));
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'feedback-export.json'; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { const msg = $("#maintMsg"); if (msg) msg.textContent = 'Export failed: ' + e.message; }
  };

  // ---- Feature flags ----
  const ffSave = $("#ffSave");
  if (ffSave) ffSave.onclick = async () => {
    const flags = {};
    ['ffLearn','ffWebshell','ffVmlab','ffAI','ffGmail','ffGithub'].forEach(id => {
      const el = $('#' + id);
      if (el) flags[id.replace('ff','')] = el.checked;
    });
    try {
      await setDoc(doc(db, "settings", "features"), { ...flags, updatedBy: user.email, updatedAt: serverTimestamp() }, { merge: true });
      const msg = $("#ffMsg"); if (msg) msg.textContent = 'Flags saved.';
    } catch(e) { const msg = $("#ffMsg"); if (msg) msg.textContent = 'Save failed: ' + e.message; }
  };
  // Load saved flags
  try {
    const flagDoc = await getDoc(doc(db, "settings", "features"));
    if (flagDoc.exists()) {
      const d = flagDoc.data();
      ['Learn','Webshell','Vmlab','AI','Gmail','Github'].forEach(f => {
        const el = $('#ff' + f);
        if (el && d[f] !== undefined) el.checked = d[f];
      });
    }
  } catch(_) {}

  // ---- System status ----
  const sysLh = $("#sysLh");
  if (sysLh) {
    try {
      const r = await fetch('/data/topics.json', { method: 'HEAD' });
      sysLh.textContent = r.ok ? 'OK' : 'error';
      sysLh.style.color = r.ok ? '#3fb950' : '#f85149';
    } catch(_) { sysLh.textContent = 'unreachable'; sysLh.style.color = '#f85149'; }
  }
  const sysBundle = $("#sysBundle");
  if (sysBundle) {
    const scripts = document.querySelectorAll('script[src]');
    sysBundle.textContent = scripts.length + ' scripts loaded';
  }
  const sysDeploy = $("#sysDeploy");
  if (sysDeploy) {
    try {
      const r = await fetch('/js/auth.js', { method: 'HEAD' });
      const lm = r.headers.get('last-modified');
      sysDeploy.textContent = lm ? new Date(lm).toLocaleDateString() : 'unknown';
    } catch(_) { sysDeploy.textContent = 'unknown'; }
  }

  // ---- Quick actions ----
  const admBackup = $("#admBackup");
  if (admBackup) admBackup.onclick = async () => {
    try {
      const [usersSnap, wlSnap, annSnap] = await Promise.all([
        getDocs(collection(db, "users")),
        getDoc(WL_REF()),
        getDoc(ANN_REF()),
      ]);
      const backup = {
        exportedAt: new Date().toISOString(),
        users: usersSnap.docs.map(d => ({ id: d.id, ...d.data() })),
        whitelist: wlSnap.exists() ? wlSnap.data() : {},
        announcement: annSnap.exists() ? annSnap.data() : {},
      };
      const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a'); a.href = url; a.download = 'darknode-backup-' + new Date().toISOString().slice(0,10) + '.json'; a.click();
      URL.revokeObjectURL(url);
    } catch(e) { alert('Backup failed: ' + e.message); }
  };

  const admMsgAll = $("#admMsgAll");
  if (admMsgAll) admMsgAll.onclick = () => {
    const msg = prompt('Message to all users (shown as announcement):');
    if (!msg) return;
    const annText = $("#annText");
    if (annText) { annText.value = msg; }
    alert('Set the announcement text. Click Publish to send it.');
  };

  // ---- Email panel ----
  const emailTarget = $("#emailTarget");
  const emailOneRow = $("#emailOneRow");
  const emailCount = $("#emailCount");
  const emailMsg = $("#emailMsg");
  let emailMode = "one";

  if (emailTarget) {
    emailTarget.querySelectorAll("button").forEach((b) => {
      b.onclick = () => {
        emailTarget.querySelectorAll("button").forEach((x) => x.classList.remove("on"));
        b.classList.add("on");
        emailMode = b.dataset.v;
        if (emailOneRow) emailOneRow.style.display = emailMode === "one" ? "" : "none";
        if (emailCount) emailCount.textContent = emailMode === "all" ? users.filter((u) => u.email).length + " recipients" : "";
      };
    });
  }

  // Quick templates
  const templates = {
    downtime: {
      subject: "We're sorry — Darknode was briefly down",
      body: "Hi there,\n\nWe wanted to reach out and apologize for the brief downtime on darknode.ai yesterday. We know you rely on the platform and we take uptime seriously.\n\nWhat happened: A configuration change caused the site to become temporarily unavailable. We identified and resolved the issue, and the platform is now fully operational.\n\nWhat we're doing: We've added monitoring to prevent this from happening again.\n\nThank you for your patience and for being part of the Darknode community.\n\nBest,\nThe Darknode Team\ncontact@darknode.ai"
    },
    update: {
      subject: "What's new on Darknode",
      body: "Hi there,\n\nWe've shipped some updates to Darknode:\n\n- [Feature 1]\n- [Feature 2]\n- [Bug fix]\n\nCheck it out at darknode.ai\n\nBest,\nThe Darknode Team"
    },
    welcome: {
      subject: "Welcome to Darknode",
      body: "Welcome to Darknode!\n\nThanks for signing up. Here's what you can do:\n\n- Explore 120+ security tools and cheat sheets\n- Use the Nexus AI coding agent\n- Practice in our security labs\n- Track your progress in the Learn Hub\n\nGet started at darknode.ai\n\nBest,\nThe Darknode Team\ncontact@darknode.ai"
    },
    security: {
      subject: "Security Notice — Darknode",
      body: "Hi there,\n\nThis is a security notice from Darknode.\n\n[Describe the security event]\n\nWhat you should do:\n- [Action item 1]\n- [Action item 2]\n\nIf you have questions, reply to this email.\n\nBest,\nThe Darknode Team\ncontact@darknode.ai"
    }
  };

  main.querySelectorAll(".emailTpl").forEach((b) => {
    b.onclick = () => {
      const tpl = templates[b.dataset.tpl];
      if (!tpl) return;
      const subj = $("#emailSubject"), body = $("#emailBody");
      if (subj) subj.value = tpl.subject;
      if (body) body.value = tpl.body;
      if (emailMsg) emailMsg.textContent = "Template loaded: " + b.dataset.tpl;
    };
  });

  // Send via Gmail (mailto or Gmail compose URL)
  const emailSend = $("#emailSend");
  if (emailSend) emailSend.onclick = () => {
    const subj = ($("#emailSubject")?.value || "").trim();
    const body = ($("#emailBody")?.value || "").trim();
    if (!subj || !body) { if (emailMsg) emailMsg.textContent = "Subject and body required."; return; }

    let to;
    if (emailMode === "one") {
      to = ($("#emailTo")?.value || "").trim();
      if (!to) { if (emailMsg) emailMsg.textContent = "Enter a recipient email."; return; }
    } else {
      const emails = users.filter((u) => u.email && u.email !== OWNER_EMAIL).map((u) => u.email);
      if (!emails.length) { if (emailMsg) emailMsg.textContent = "No users to email."; return; }
      to = emails.join(",");
    }

    const gmailUrl = "https://mail.google.com/mail/?view=cm"
      + "&to=" + encodeURIComponent(to)
      + "&su=" + encodeURIComponent(subj)
      + "&body=" + encodeURIComponent(body)
      + "&from=" + encodeURIComponent("contact@darknode.ai");
    window.open(gmailUrl, "_blank", "noopener,noreferrer");
    if (emailMsg) emailMsg.textContent = emailMode === "all"
      ? "Opened Gmail with " + users.filter((u) => u.email && u.email !== OWNER_EMAIL).length + " recipients"
      : "Opened Gmail draft to " + to;
  };

  // Copy as text
  const emailCopy = $("#emailCopyDraft");
  if (emailCopy) emailCopy.onclick = () => {
    const subj = ($("#emailSubject")?.value || "").trim();
    const body = ($("#emailBody")?.value || "").trim();
    const draft = "Subject: " + subj + "\n\n" + body;
    navigator.clipboard?.writeText(draft);
    if (emailMsg) emailMsg.textContent = "Draft copied to clipboard.";
  };

  // ---- Danger zone ----
  const admPurge = $("#admPurgeData");
  if (admPurge) admPurge.onclick = async () => {
    const msg = $("#dangerMsg");
    if (!confirm('DANGER: This permanently deletes ALL user data. Are you absolutely sure?')) return;
    if (prompt('Type DELETE to confirm:') !== 'DELETE') return;
    let count = 0;
    for (const u of users) {
      if (u.email === OWNER_EMAIL) continue;
      try { await deleteDoc(doc(db, "users", u.uid)); count++; } catch(_) {}
    }
    if (msg) msg.textContent = 'Purged ' + count + ' users.';
    loadUsers();
  };

  const admRevoke = $("#admRevokeAll");
  if (admRevoke) admRevoke.onclick = () => {
    const msg = $("#dangerMsg");
    if (msg) msg.textContent = 'Session revocation requires Firebase Admin SDK (server-side). Use the Firebase Console to revoke refresh tokens.';
  };

  // Load analytics + activity
  loadAnalytics();
  loadActivityLog();
}
