// Saved workspace — bookmark tools/sections and keep engagement notes.
// Signed-in: persisted per-user in Firestore (users/{uid}.workspace).
// Signed-out: localStorage fallback. Same API either way.
import { db } from "/js/firebase.js";
import { doc, getDoc, setDoc } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const LS = "sw_saved";
let state = { bookmarks: [], notes: "" };
let uid = null, noteTimer = null;

const lsLoad = () => { try { return JSON.parse(localStorage.getItem(LS)) || { bookmarks: [], notes: "" }; } catch (_) { return { bookmarks: [], notes: "" }; } };
const lsSave = () => { try { localStorage.setItem(LS, JSON.stringify(state)); } catch (_) {} };
const emit = () => { try { document.dispatchEvent(new CustomEvent("sentinel:saved")); } catch (_) {} };

export async function initSaved(user) {
  uid = user ? user.uid : null;
  if (uid) {
    try { const s = await getDoc(doc(db, "users", uid)); const w = s.exists() && s.data().workspace; state = { bookmarks: (w && w.bookmarks) || [], notes: (w && w.notes) || "" }; }
    catch (_) { state = lsLoad(); }
  } else { state = lsLoad(); }
  emit();
}
async function persist() {
  if (uid) { try { await setDoc(doc(db, "users", uid), { workspace: { bookmarks: state.bookmarks, notes: state.notes, updatedAt: Date.now() } }, { merge: true }); return; } catch (_) {} }
  lsSave();
}
export function isBookmarked(id) { return state.bookmarks.some((b) => b.id === id); }
export function toggleBookmark(item) {
  if (isBookmarked(item.id)) state.bookmarks = state.bookmarks.filter((b) => b.id !== item.id);
  else state.bookmarks.push({ id: item.id, label: item.label, sec: item.sec || "tools" });
  persist(); emit(); return isBookmarked(item.id);
}
export function getBookmarks() { return state.bookmarks.slice(); }
export function onSaved(cb) { document.addEventListener("sentinel:saved", cb); }

export function renderSaved(main, show) {
  const draw = () => {
    const bm = getBookmarks();
    main.innerHTML = `
      <h1 class="pg-h1">Saved</h1>
      <p class="muted pg-sub">Your bookmarked tools and engagement notes.${uid ? " Synced to your account across devices." : " Stored in this browser — sign in to sync across devices."}</p>
      <div class="home-cols">
        <div class="hc-main">
          <div class="panel">
            <div class="panel-h"><h2 class="pg-h2" style="margin:0">Bookmarks</h2><span class="chip">${bm.length}</span></div>
            ${bm.length ? `<div class="saved-list">${bm.map((b) => `<div class="saved-row"><button class="saved-go" data-go="${esc(b.sec)}">${esc(b.label)}</button><span class="muted" style="font-size:.74rem">${esc(b.sec)}</span><button class="saved-x" data-rm="${esc(b.id)}" title="remove">&times;</button></div>`).join("")}</div>`
              : `<p class="muted" style="font-size:.85rem">No bookmarks yet. Tap the ★ on any tool to save it here.</p>`}
          </div>
        </div>
        <div class="hc-side">
          <div class="panel">
            <div class="panel-h"><h2 class="pg-h2" style="margin:0">Engagement notes</h2><span class="muted" id="noteState" style="font-size:.72rem"></span></div>
            <textarea class="tk-in" id="notes" rows="14" placeholder="Scope, creds, findings, to-do…" style="width:100%;font-family:var(--mono,ui-monospace,monospace)">${esc(state.notes)}</textarea>
          </div>
        </div>
      </div>`;
    main.querySelectorAll("[data-go]").forEach((b) => (b.onclick = () => show(b.dataset.go)));
    main.querySelectorAll("[data-rm]").forEach((b) => (b.onclick = () => { toggleBookmark({ id: b.dataset.rm }); }));
    const ta = main.querySelector("#notes"), st = main.querySelector("#noteState");
    ta.oninput = () => { state.notes = ta.value; st.textContent = "saving…"; clearTimeout(noteTimer); noteTimer = setTimeout(() => { persist(); st.textContent = "saved"; setTimeout(() => (st.textContent = ""), 1200); }, 700); };
  };
  draw();
  onSaved(() => { if (document.body.contains(main)) draw(); });
}
