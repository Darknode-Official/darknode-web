// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Beta Lab — a preview mode. Everything here is a PROTOTYPE of something that
// might get built; nothing in this mode is a shipped tool. Two live-data pieces
// let the lab grow without a hosting redeploy:
//   - demoTools   (Firestore): extra demos are published as docs and appear live.
//   - toolRequests(Firestore): anyone can ask for a tool; their name + idea show.
// The flagship prototype is the from-scratch game synthesizer, which runs fully
// in the browser (no Firestore needed), so the lab is useful even offline.

import { db } from "/js/firebase.js?v=20261007a";
import { collection, query, orderBy, limit, onSnapshot, addDoc, serverTimestamp } from "https://www.gstatic.com/firebasejs/12.17.0/firebase-firestore.js";
import { synthFromScratch } from "/js/engine/gamegen-scratch.js?v=20261008b";

let showToast = (m) => { try { console.log(m); } catch (_) {} };
import("/js/toast.js").then((m) => { if (m.showToast) showToast = m.showToast; }).catch(() => {});

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const subs = [];        // Firestore unsubscribe fns for this view
function clearSubs() { while (subs.length) { try { subs.pop()(); } catch (_) {} } }

// Self-contained styles, injected once. Scoped under .beta-wrap / .beta-ask so
// they never leak into the rest of the console.
const STYLE_ID = "beta-lab-styles";
function injectStyles() {
  if (document.getElementById(STYLE_ID)) return;
  const s = document.createElement("style");
  s.id = STYLE_ID;
  s.textContent = `
  .beta-wrap{max-width:1180px;margin:0 auto;padding:18px 20px 60px}
  .beta-head{margin:6px 0 22px}
  .beta-head h1{font-size:28px;margin:0 0 6px;display:flex;align-items:center;gap:12px;letter-spacing:.3px}
  .beta-pill{font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.4px;color:#0b0b12;background:linear-gradient(90deg,#5ad1ff,#8cff5a);padding:3px 10px;border-radius:999px}
  .beta-lede{color:#9aa6bd;max-width:760px;line-height:1.55;margin:0}
  .beta-card{background:rgba(18,21,32,.72);border:1px solid rgba(120,140,190,.18);border-radius:14px;padding:20px;margin:0 0 20px;box-shadow:0 1px 0 rgba(255,255,255,.03) inset}
  .beta-flagship{border-color:rgba(90,209,255,.32);box-shadow:0 0 0 1px rgba(90,209,255,.12),0 10px 40px -20px rgba(90,209,255,.5)}
  .beta-card-head{display:flex;justify-content:space-between;gap:16px;align-items:flex-start;margin-bottom:14px}
  .beta-card h3{margin:0 0 6px;font-size:18px;display:flex;align-items:center;gap:10px;flex-wrap:wrap}
  .beta-tag{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:#9fe6ff;background:rgba(90,209,255,.12);border:1px solid rgba(90,209,255,.3);padding:2px 8px;border-radius:6px}
  .beta-sub{color:#8f9bb3;font-size:13px;line-height:1.5;margin:0;max-width:720px}
  .beta-by{color:#6f7a90;font-style:italic}
  .beta-gen{display:grid;grid-template-columns:1fr 1fr;gap:20px;align-items:start}
  .beta-gen-controls{display:flex;flex-direction:column;gap:12px;min-width:0}
  .beta-input{width:100%;box-sizing:border-box;background:#0c0f18;border:1px solid rgba(120,140,190,.3);color:#e8eefc;border-radius:9px;padding:11px 13px;font-size:14px;font-family:inherit;outline:none}
  .beta-input:focus{border-color:#5ad1ff;box-shadow:0 0 0 3px rgba(90,209,255,.15)}
  textarea.beta-input{resize:vertical;line-height:1.45}
  .beta-gen-row{display:flex;gap:8px;flex-wrap:wrap}
  .beta-chips{display:flex;gap:7px;flex-wrap:wrap}
  .beta-chip{background:rgba(90,209,255,.08);border:1px solid rgba(90,209,255,.22);color:#bfe9ff;font-size:12px;padding:5px 10px;border-radius:999px;cursor:pointer;font-family:inherit}
  .beta-chip:hover{background:rgba(90,209,255,.18)}
  .beta-readback{color:#cdd6ea;font-size:13px;line-height:1.5;margin:2px 0 0;min-height:1em}
  .beta-readback strong{color:#8cff5a}
  .beta-caveat{color:#ffcf6b;font-size:12.5px;line-height:1.5;margin:0}
  .beta-gen-preview{min-width:0}
  .beta-frame{width:100%;aspect-ratio:11/16;max-height:620px;border:1px solid rgba(120,140,190,.28);border-radius:10px;background:#05050c;display:block}
  .beta-frame-wide{aspect-ratio:16/10;max-height:460px}
  .beta-code{margin:14px 0 0;background:#06080f;border:1px solid rgba(120,140,190,.2);border-radius:10px;padding:14px;max-height:340px;overflow:auto;font-size:12px;color:#aeb8cf;white-space:pre;line-height:1.5}
  .beta-btn,.beta-wrap .btn{cursor:pointer}
  .beta-req-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:8px}
  .beta-req{display:flex;gap:12px;align-items:baseline;padding:9px 12px;background:rgba(10,13,22,.6);border:1px solid rgba(120,140,190,.14);border-radius:9px}
  .beta-req-name{color:#5ad1ff;font-weight:600;font-size:13px;flex:0 0 auto;max-width:34%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .beta-req-idea{color:#c4cde0;font-size:13px;line-height:1.4}
  .beta-ask{display:flex;flex-direction:column;gap:9px}
  .beta-ask-title{margin:0;font-size:15px;color:#e8eefc}
  .beta-ask-sub{margin:0;color:#8f9bb3;font-size:12.5px;line-height:1.45}
  .beta-ask-row{display:flex;align-items:center;justify-content:space-between;gap:10px}
  .beta-ask-count{color:#6f7a90;font-size:11px}
  .beta-ask-msg{margin:0;font-size:12.5px;color:#8cff5a;min-height:1em}
  @media (max-width:760px){.beta-gen{grid-template-columns:1fr}.beta-frame{aspect-ratio:11/16;max-height:70vh}.beta-req-name{max-width:40%}}
  `;
  document.head.appendChild(s);
}

// --------------------------------------------------------------------------
// The from-scratch game synthesizer prototype (in-browser, deterministic).
// --------------------------------------------------------------------------
function gamegenSection() {
  return `
  <section class="beta-card beta-flagship">
    <div class="beta-card-head">
      <div>
        <h3>From-scratch game synthesizer <span class="beta-tag">prototype</span></h3>
        <p class="beta-sub">Describe a game in plain words. There is no genre template behind it — your words are parsed into an entity / behaviour / rule graph and the program is emitted line by line from atomic primitives. Deterministic and offline: no model, no network. It is honest when a described mechanic is outside its vocabulary.</p>
      </div>
    </div>
    <div class="beta-gen">
      <div class="beta-gen-controls">
        <input id="bgPrompt" class="beta-input" type="text" autocomplete="off"
          placeholder="e.g. a shooter where I fire homing balls at bouncing squares" />
        <div class="beta-gen-row">
          <button id="bgBuild" class="btn">Build it</button>
          <button id="bgSource" class="btn btn-ghost" type="button">View source</button>
          <button id="bgDownload" class="btn btn-ghost" type="button">Download .html</button>
        </div>
        <div class="beta-chips" id="bgChips"></div>
        <p id="bgReadback" class="beta-readback"></p>
        <p id="bgCaveat" class="beta-caveat"></p>
      </div>
      <div class="beta-gen-preview">
        <iframe id="bgFrame" class="beta-frame" title="Game preview" sandbox="allow-scripts"></iframe>
      </div>
    </div>
    <pre id="bgCode" class="beta-code" hidden></pre>
  </section>`;
}

function wireGamegen(root) {
  const promptEl = root.querySelector("#bgPrompt");
  const frame = root.querySelector("#bgFrame");
  const codeEl = root.querySelector("#bgCode");
  const readback = root.querySelector("#bgReadback");
  const caveatEl = root.querySelector("#bgCaveat");
  const chips = root.querySelector("#bgChips");
  let current = null;

  const EXAMPLES = [
    "a shooter where I fire homing balls at bouncing squares",
    "dodge the falling red triangles",
    "catch the falling green gems in a basket",
    "endless runner, jump over obstacles",
    "survive a swarm of zigzag asteroids",
  ];
  chips.innerHTML = EXAMPLES.map((e) => `<button class="beta-chip" type="button">${esc(e)}</button>`).join("");
  chips.querySelectorAll(".beta-chip").forEach((b) => (b.onclick = () => { promptEl.value = b.textContent; build(); }));

  function build() {
    const req = promptEl.value.trim();
    if (!req) { showToast("Describe a game first.", "info"); return; }
    const g = synthFromScratch(req);
    if (!g) {
      readback.textContent = "";
      caveatEl.textContent = "That does not read as a game I can build — try words like shoot, dodge, catch, jump, or name a shape and a colour.";
      frame.removeAttribute("srcdoc");
      current = null;
      return;
    }
    current = g;
    frame.srcdoc = g.code;
    codeEl.textContent = g.code;
    readback.innerHTML = "<strong>Built:</strong> " + esc(g.ir.describe);
    caveatEl.textContent = g.caveat || "";
  }

  root.querySelector("#bgBuild").onclick = build;
  promptEl.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); build(); } });
  root.querySelector("#bgSource").onclick = () => {
    codeEl.hidden = !codeEl.hidden;
    root.querySelector("#bgSource").textContent = codeEl.hidden ? "View source" : "Hide source";
  };
  root.querySelector("#bgDownload").onclick = () => {
    if (!current) { showToast("Build a game first.", "info"); return; }
    const blob = new Blob([current.code], { type: "text/html" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = (current.title || "game").toLowerCase().replace(/[^a-z0-9]+/g, "-") + ".html";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  };
  // first paint
  promptEl.value = EXAMPLES[0];
  build();
}

// --------------------------------------------------------------------------
// Live demo gallery (Firestore demoTools) — published without a redeploy.
// --------------------------------------------------------------------------
function renderDemoCard(d) {
  const author = d.author ? `<span class="beta-by">proposed by ${esc(d.author)}</span>` : "";
  const status = esc(d.status || "concept");
  if (d.kind === "html" && typeof d.html === "string") {
    return `<section class="beta-card">
      <div class="beta-card-head"><div><h3>${esc(d.name || "Untitled demo")} <span class="beta-tag">${status}</span></h3>
      <p class="beta-sub">${esc(d.tagline || "")} ${author}</p></div></div>
      <iframe class="beta-frame beta-frame-wide" title="${esc(d.name || "demo")}" sandbox="allow-scripts" srcdoc="${esc(d.html)}"></iframe>
    </section>`;
  }
  // concept / link card (no runnable code)
  const link = d.url ? `<a class="btn btn-ghost" href="${esc(d.url)}" target="_blank" rel="noopener">Learn more</a>` : "";
  return `<section class="beta-card">
    <div class="beta-card-head"><div><h3>${esc(d.name || "Untitled")} <span class="beta-tag">${status}</span></h3>
    <p class="beta-sub">${esc(d.tagline || d.description || "")} ${author}</p></div></div>
    ${link}
  </section>`;
}

function subscribeDemos(mount) {
  try {
    const q = query(collection(db, "demoTools"), orderBy("order", "asc"), limit(30));
    subs.push(onSnapshot(q, (snap) => {
      const cards = [];
      snap.forEach((doc) => cards.push(renderDemoCard(doc.data())));
      mount.innerHTML = cards.join("") || "";
    }, () => { mount.innerHTML = ""; }));
  } catch (_) { mount.innerHTML = ""; }
}

// --------------------------------------------------------------------------
// Request board (Firestore toolRequests) — read-only list of asks.
// --------------------------------------------------------------------------
function subscribeRequests(mount) {
  try {
    const q = query(collection(db, "toolRequests"), orderBy("ts", "desc"), limit(40));
    subs.push(onSnapshot(q, (snap) => {
      const rows = [];
      snap.forEach((doc) => { const r = doc.data(); rows.push(
        `<li class="beta-req"><span class="beta-req-name">${esc(r.name || "anonymous")}</span><span class="beta-req-idea">${esc(r.idea || "")}</span></li>`); });
      mount.innerHTML = rows.length
        ? `<ul class="beta-req-list">${rows.join("")}</ul>`
        : `<p class="beta-sub">No requests yet. Be the first — ask from the sign-in screen or your profile menu.</p>`;
    }, () => { mount.innerHTML = `<p class="beta-sub">Request board is offline right now.</p>`; }));
  } catch (_) { mount.innerHTML = `<p class="beta-sub">Request board is offline right now.</p>`; }
}

// --------------------------------------------------------------------------
// Shared request form — mounted in the sign-in screen AND the profile area.
// Writes {name, idea, uid, ts} to toolRequests; validated again by the Rules.
// --------------------------------------------------------------------------
export function mountRequestForm(container, opts = {}) {
  injectStyles();
  const user = opts.user || null;
  const presetName = user ? (user.displayName || (user.email ? user.email.split("@")[0] : "")) : "";
  container.innerHTML = `
    <form class="beta-ask" novalidate>
      <h4 class="beta-ask-title">Request a tool for the Beta Lab</h4>
      <p class="beta-ask-sub">Suggest a tool you want prototyped. Your name and idea appear on the public request board.</p>
      <input class="beta-input" id="askName" maxlength="60" autocomplete="name" placeholder="Your name" value="${esc(presetName)}" />
      <textarea class="beta-input" id="askIdea" maxlength="280" rows="3" placeholder="The tool you'd like to see demoed..."></textarea>
      <div class="beta-ask-row"><span class="beta-ask-count" id="askCount">0 / 280</span>
      <button class="btn" type="submit" id="askSend">Send request</button></div>
      <p class="beta-ask-msg" id="askMsg"></p>
    </form>`;
  const form = container.querySelector("form");
  const nameEl = container.querySelector("#askName");
  const ideaEl = container.querySelector("#askIdea");
  const countEl = container.querySelector("#askCount");
  const msg = container.querySelector("#askMsg");
  ideaEl.addEventListener("input", () => { countEl.textContent = ideaEl.value.length + " / 280"; });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const name = nameEl.value.trim().slice(0, 60) || "anonymous";
    const idea = ideaEl.value.trim();
    if (idea.length < 3) { msg.textContent = "Add a little more detail about the tool."; return; }
    const btn = container.querySelector("#askSend");
    btn.disabled = true; msg.textContent = "Sending...";
    try {
      await addDoc(collection(db, "toolRequests"), {
        name, idea, uid: user ? user.uid : null, ts: Date.now(), createdAt: serverTimestamp(),
      });
      ideaEl.value = ""; countEl.textContent = "0 / 280";
      msg.textContent = "Thanks — your request is on the board.";
      showToast("Tool request submitted.", "success");
    } catch (err) {
      msg.textContent = "Could not send right now. Please try again later.";
    } finally { btn.disabled = false; }
  });
}

// --------------------------------------------------------------------------
// The mode entry point.
// --------------------------------------------------------------------------
export function renderBetaLab(main) {
  clearSubs();
  injectStyles();
  main.innerHTML = `
  <div class="beta-wrap">
    <header class="beta-head">
      <h1>Beta Lab <span class="beta-pill">preview</span></h1>
      <p class="beta-lede">A window into what might get built. Everything here is a prototype or a concept — nothing in this mode is a shipped tool. New demos can appear here live, without a site update.</p>
    </header>

    ${gamegenSection()}

    <div id="betaDemos"></div>

    <section class="beta-card">
      <div class="beta-card-head"><div>
        <h3>Request board</h3>
        <p class="beta-sub">Tools people have asked to see prototyped. Add yours from the sign-in screen (if you're signed out) or your profile menu.</p>
      </div></div>
      <div id="betaReqBoard"><p class="beta-sub">Loading requests...</p></div>
    </section>
  </div>`;

  const flagship = main.querySelector(".beta-flagship");
  if (flagship) wireGamegen(main);
  subscribeDemos(main.querySelector("#betaDemos"));
  subscribeRequests(main.querySelector("#betaReqBoard"));
}

export function cleanupBetaLab() { clearSubs(); }
