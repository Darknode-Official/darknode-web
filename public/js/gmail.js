// Gmail integration for the web console. Connect your Google account (Gmail
// read + compose scopes), browse Inbox / Sent / Spam / Drafts, open a message,
// and hand it to the AI to draft or edit a reply — or save that draft back to
// Gmail. The OAuth access token lives only in this browser (localStorage).
//
// SETUP (one-time, in YOUR Google Cloud project behind this site's OAuth client):
//   • enable the Gmail API
//   • add scopes gmail.readonly + gmail.compose to the OAuth consent screen
//   • add your account as a test user (sensitive scopes are unverified by default)
import { auth } from "/js/firebase.js";
import { GoogleAuthProvider, signInWithPopup } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const TOK_KEY = "sw_gmail_token";
const getTok = () => { try { return localStorage.getItem(TOK_KEY) || ""; } catch (_) { return ""; } };
const setTok = (t) => { try { t ? localStorage.setItem(TOK_KEY, t) : localStorage.removeItem(TOK_KEY); } catch (_) {} };
const SCOPES = ["https://www.googleapis.com/auth/gmail.readonly", "https://www.googleapis.com/auth/gmail.compose"];
const FOLDERS = [["inbox", "Inbox", "in:inbox"], ["sent", "Sent", "in:sent"], ["spam", "Spam", "in:spam"], ["drafts", "Drafts", "in:drafts"]];
const ago = (ms) => { const s = (Date.now() - ms) / 1000; if (isNaN(s)) return ""; if (s < 3600) return Math.max(0, Math.floor(s / 60)) + "m"; if (s < 86400) return Math.floor(s / 3600) + "h"; return Math.floor(s / 86400) + "d"; };

const CID_KEY = "sw_gmail_client_id";
const getCid = () => { try { return (localStorage.getItem(CID_KEY) || "").trim(); } catch (_) { return ""; } };
const setCid = (v) => { try { v ? localStorage.setItem(CID_KEY, v) : localStorage.removeItem(CID_KEY); } catch (_) {} };

// Load Google Identity Services once (for the bring-your-own-client token flow).
let gisLoading = null;
function loadGis() {
  if (window.google && window.google.accounts && window.google.accounts.oauth2) return Promise.resolve();
  if (gisLoading) return gisLoading;
  gisLoading = new Promise((res, rej) => { const s = document.createElement("script"); s.src = "https://accounts.google.com/gsi/client"; s.async = true; s.onload = () => res(); s.onerror = () => rej(new Error("couldn't load Google's sign-in script")); document.head.appendChild(s); });
  return gisLoading;
}

async function connect() {
  const cid = getCid();
  if (cid) {
    // Option B: the user's own Web OAuth client (GIS token flow) — no test-user
    // list, but the client must have this site's origin as an authorized origin.
    await loadGis();
    return await new Promise((resolve, reject) => {
      try {
        const tc = window.google.accounts.oauth2.initTokenClient({ client_id: cid, scope: SCOPES.join(" "), prompt: "consent", callback: (r) => { if (r && r.access_token) { setTok(r.access_token); resolve(r.access_token); } else reject(new Error((r && r.error_description) || (r && r.error) || "no access token returned")); } });
        tc.requestAccessToken();
      } catch (e) { reject(e); }
    });
  }
  // Built-in: Firebase popup (works only for accounts added as test users on this site's project).
  const p = new GoogleAuthProvider();
  SCOPES.forEach((s) => p.addScope(s));
  p.setCustomParameters({ prompt: "consent" });
  const res = await signInWithPopup(auth, p);
  const cred = GoogleAuthProvider.credentialFromResult(res);
  const tok = cred && cred.accessToken;
  if (!tok) throw new Error("Google didn't return a Gmail access token — check the Gmail scopes on your OAuth consent screen");
  setTok(tok); return tok;
}
async function gapi(pathPart, opts) {
  const tok = getTok(); if (!tok) throw Object.assign(new Error("not connected"), { code: "noauth" });
  const r = await fetch("https://gmail.googleapis.com/gmail/v1/users/me" + pathPart,
    Object.assign({ headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" } }, opts || {}));
  if (r.status === 401) { setTok(""); throw Object.assign(new Error("Gmail session expired — reconnect"), { code: "expired" }); }
  if (r.status === 403) throw new Error("forbidden — is the Gmail API enabled and the scope granted? (403)");
  if (!r.ok) throw new Error("Gmail API " + r.status);
  return r.json();
}
const hdr = (m, name) => { const h = ((m.payload && m.payload.headers) || []).find((x) => x.name.toLowerCase() === name.toLowerCase()); return h ? h.value : ""; };
function decodeBody(payload) {
  if (!payload) return "";
  const b64 = (d) => { try { return decodeURIComponent(escape(atob(String(d).replace(/-/g, "+").replace(/_/g, "/")))); } catch (_) { try { return atob(String(d).replace(/-/g, "+").replace(/_/g, "/")); } catch (e) { return ""; } } };
  if (payload.mimeType === "text/plain" && payload.body && payload.body.data) return b64(payload.body.data);
  if (payload.parts) { const plain = payload.parts.find((p) => p.mimeType === "text/plain"); if (plain && plain.body && plain.body.data) return b64(plain.body.data); for (const p of payload.parts) { const t = decodeBody(p); if (t) return t; } }
  if (payload.body && payload.body.data) return b64(payload.body.data).replace(/<[^>]+>/g, " ");
  return "";
}
// Hand text to the AI assistant: stash it, then open the AI section.
function askAI(text) {
  try { sessionStorage.setItem("sw_ai_prefill", text); } catch (_) {}
  const it = document.querySelector('.side-item[data-sec="ai"]'); if (it) it.click();
}
// RFC-822 → base64url for the Gmail drafts endpoint.
function rawMessage(to, subject, body) {
  const lines = ["To: " + to, "Subject: " + subject, "Content-Type: text/plain; charset=utf-8", "MIME-Version: 1.0", "", body];
  return btoa(unescape(encodeURIComponent(lines.join("\r\n")))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function renderGmail(main) {
  const connected = !!getTok();
  main.innerHTML = `
    <h1 class="pg-h1">Gmail</h1>
    <p class="muted pg-sub">Connect your Google account to browse Inbox, Sent, Spam &amp; Drafts, read a message, and let the AI draft or edit a reply. Your token stays in this browser.</p>
    <div class="card" style="max-width:900px">
      <div class="row" style="gap:8px;flex-wrap:wrap;align-items:center">
        ${connected
          ? `<span class="sev low">connected</span><button class="btn ghost" id="gmDisc">Disconnect</button><button class="btn ghost" id="gmCompose">Compose</button>`
          : `<button class="btn" id="gmConn">Connect Gmail</button><span class="muted" style="font-size:.82rem">${getCid() ? "using your own Google client" : "requires the Gmail API + scopes on your Google OAuth consent screen"}</span>`}
      </div>
      ${connected ? "" : `
      <details style="margin-top:12px"${getCid() ? " open" : ""}><summary class="muted" style="font-size:.82rem;cursor:pointer">Use your own Google client (so anyone can connect — no test-user list)</summary>
        <p class="muted" style="font-size:.78rem;margin:6px 0">Create a <b>Web application</b> OAuth client in your own Google Cloud project (Gmail API enabled), and add this site's URL as an <b>Authorized JavaScript origin</b>. Paste the Client ID below. No secret needed. Leave blank to use the built-in client (test users only).</p>
        <div class="row" style="gap:8px;flex-wrap:wrap"><input class="tk-f" id="gmCid" placeholder="Your Web client ID (…apps.googleusercontent.com)" value="${esc(getCid())}" style="flex:1;min-width:240px"><button class="btn ghost" id="gmCidSave">Save</button><button class="btn ghost" id="gmCidClear">Use built-in</button></div>
        <p class="muted" id="gmCidNote" style="font-size:.76rem;margin-top:6px"></p></details>`}
      ${connected ? `
      <div class="cs-filter" id="gmTabs" style="margin-top:12px">${FOLDERS.map((f, i) => `<button class="chip${i === 0 ? " on" : ""}" data-f="${f[0]}">${f[1]}</button>`).join("")}</div>
      <div class="row" style="gap:8px;margin:8px 0"><input class="tk-f" id="gmSearch" placeholder="search (Gmail query, e.g. from:boss is:unread)" style="flex:1;min-width:160px"><button class="btn ghost" id="gmGo">Search</button></div>
      <div id="gmList" style="min-height:80px"></div>
      <div id="gmView"></div>` : ""}
    </div>`;
  const $ = (s) => main.querySelector(s);
  const err = (m) => { const l = $("#gmList") || main; l.innerHTML = `<p class="muted" style="color:var(--bad)">${esc(m)}</p>`; };

  if (!connected) {
    const b = $("#gmConn"); if (b) b.onclick = async () => { b.disabled = true; b.textContent = "opening Google…"; try { await connect(); renderGmail(main); } catch (e) { b.disabled = false; b.textContent = "Connect Gmail"; alert("Gmail connect failed: " + (e && e.message || e)); } };
    const cs = $("#gmCidSave"); if (cs) cs.onclick = () => { setCid($("#gmCid").value.trim()); const n = $("#gmCidNote"); if (n) n.textContent = getCid() ? "saved — now click Connect Gmail." : "cleared — using the built-in client."; };
    const cc = $("#gmCidClear"); if (cc) cc.onclick = () => { setCid(""); renderGmail(main); };
    return;
  }

  $("#gmDisc").onclick = () => { setTok(""); renderGmail(main); };
  $("#gmCompose").onclick = () => openCompose(main, "", "", "");
  let folder = "inbox";
  const q = () => (($("#gmSearch").value || "").trim() || (FOLDERS.find((f) => f[0] === folder) || [])[2] || "in:inbox");

  async function loadList() {
    const list = $("#gmList"); list.innerHTML = `<p class="muted">loading…</p>`; $("#gmView").innerHTML = "";
    try {
      const res = await gapi("/messages?maxResults=20&q=" + encodeURIComponent(q()));
      const ids = (res.messages || []).map((m) => m.id);
      if (!ids.length) { list.innerHTML = `<p class="muted">no messages.</p>`; return; }
      const metas = await Promise.all(ids.map((id) => gapi("/messages/" + id + "?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date").catch(() => null)));
      list.innerHTML = metas.filter(Boolean).map((m) => {
        const unread = (m.labelIds || []).includes("UNREAD");
        return `<div class="gh-row gm-row" data-id="${esc(m.id)}" style="cursor:pointer">
          <div class="gh-desc" style="flex:1;min-width:0"><b>${unread ? "● " : ""}${esc(hdr(m, "From").replace(/<.*/, "").trim() || hdr(m, "From"))}</b><br><span class="muted">${esc(hdr(m, "Subject") || "(no subject)")}</span><br><span class="muted" style="font-size:.78rem">${esc((m.snippet || "").slice(0, 90))}</span></div>
          <span class="muted" style="font-size:.75rem">${esc(ago(+(m.internalDate || 0)))}</span></div>`;
      }).join("");
    } catch (e) { if (e.code === "expired" || e.code === "noauth") renderGmail(main); else err(e.message); }
  }
  async function openMsg(id) {
    const v = $("#gmView"); v.innerHTML = `<p class="muted">opening…</p>`;
    try {
      const m = await gapi("/messages/" + id + "?format=full");
      const from = hdr(m, "From"), subj = hdr(m, "Subject"), body = decodeBody(m.payload);
      v.innerHTML = `<div class="card" style="margin-top:10px;background:var(--card2)">
        <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b>${esc(subj || "(no subject)")}</b><span class="muted" style="font-size:.8rem">${esc(from)}</span></div>
        <pre style="white-space:pre-wrap;word-break:break-word;margin:10px 0;font-size:.86rem;max-height:340px;overflow:auto">${esc(body).slice(0, 12000)}</pre>
        <div class="row" style="gap:8px;flex-wrap:wrap"><button class="btn" id="gmAI">Draft a reply with AI</button><button class="btn ghost" id="gmAIedit">Summarize with AI</button><button class="btn ghost" id="gmReply">Reply / draft</button></div></div>`;
      const reEmail = (from.match(/<([^>]+)>/) || [null, from])[1];
      v.querySelector("#gmAI").onclick = () => askAI("Draft a concise, friendly reply to this email. Return only the reply body.\n\nFrom: " + from + "\nSubject: " + subj + "\n\n" + body.slice(0, 6000));
      v.querySelector("#gmAIedit").onclick = () => askAI("Summarize this email in 3 bullet points and list any action items.\n\nSubject: " + subj + "\n\n" + body.slice(0, 6000));
      v.querySelector("#gmReply").onclick = () => openCompose(main, reEmail, subj && /^re:/i.test(subj) ? subj : "Re: " + subj, "\n\n---\n" + body.slice(0, 2000));
    } catch (e) { if (e.code === "expired") renderGmail(main); else v.innerHTML = `<p class="muted" style="color:var(--bad)">${esc(e.message)}</p>`; }
  }
  $("#gmTabs").onclick = (e) => { const b = e.target.closest(".chip"); if (!b) return; main.querySelectorAll("#gmTabs .chip").forEach((x) => x.classList.toggle("on", x === b)); folder = b.dataset.f; $("#gmSearch").value = ""; loadList(); };
  $("#gmGo").onclick = loadList;
  $("#gmSearch").onkeydown = (e) => { if (e.key === "Enter") loadList(); };
  $("#gmList").onclick = (e) => { const r = e.target.closest(".gm-row"); if (r) openMsg(r.dataset.id); };
  loadList();
}

function openCompose(main, to, subject, quoted) {
  const v = main.querySelector("#gmView") || main;
  const esc2 = esc;
  v.innerHTML = `<div class="card" style="margin-top:10px;background:var(--card2)">
    <div class="set-lbl">Compose (saves as a Gmail draft — never auto-sends)</div>
    <input class="tk-f" id="gmTo" placeholder="To" value="${esc2(to || "")}" style="width:100%;margin:4px 0">
    <input class="tk-f" id="gmSubj" placeholder="Subject" value="${esc2(subject || "")}" style="width:100%;margin:4px 0">
    <textarea class="tk-f" id="gmBody" rows="8" placeholder="Write your message…" style="width:100%;margin:4px 0">${esc2(quoted || "")}</textarea>
    <div class="row" style="gap:8px;flex-wrap:wrap"><button class="btn" id="gmSave">Save to Gmail drafts</button><button class="btn ghost" id="gmDraftAI">Write it with AI</button><span class="muted" id="gmMsg" style="font-size:.82rem"></span></div></div>`;
  const $ = (s) => v.querySelector(s);
  $("#gmDraftAI").onclick = () => askAI("Write an email. To: " + ($("#gmTo").value || "?") + ". Subject: " + ($("#gmSubj").value || "(none)") + ". Goal: " + ($("#gmBody").value || "(describe the goal in the AI chat)") + "\nReturn only the email body.");
  $("#gmSave").onclick = async () => {
    const to = $("#gmTo").value.trim(), subj = $("#gmSubj").value.trim(), body = $("#gmBody").value;
    if (!to) { $("#gmMsg").textContent = "add a recipient"; return; }
    $("#gmMsg").textContent = "saving…";
    try { await gapi("/drafts", { method: "POST", body: JSON.stringify({ message: { raw: rawMessage(to, subj, body) } }) }); $("#gmMsg").textContent = "saved to Gmail drafts ✓"; }
    catch (e) { $("#gmMsg").textContent = "save failed: " + (e && e.message || e); }
  };
}
