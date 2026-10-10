// ============================================================================
// Darknode Deck — an experimental spatial UI (admin-only preview).
//
// Not a Mac clone: it borrows a few macOS idioms people already know (a dock, a
// Launchpad-style app grid, traffic-light window chrome, a Spotlight command
// palette, and the Downloads "stack" fan-out) and reassembles them into a dark,
// glassmorphic command deck for Darknode. Goal: easy to navigate (Launchpad +
// Spotlight get you anywhere in two keystrokes) yet powerful (free-floating,
// draggable, stackable tool windows).
//
// Self-contained and dependency-free. renderDeck(host, { groups, onOpen, onExit })
// mounts a full-screen overlay and returns a teardown function. No emojis — all
// iconography is CSS/initial-based.
// ============================================================================

const COLORS = {
  blue: "#3b82f6", cyan: "#06b6d4", orange: "#f59e0b", red: "#ef4444",
  green: "#22c55e", purple: "#a855f7", violet: "#8b5cf6", emerald: "#10b981",
  slate: "#64748b", teal: "#14b8a6", pink: "#ec4899", amber: "#f59e0b",
  indigo: "#6366f1", rose: "#f43f5e", lime: "#84cc16", sky: "#0ea5e9",
};
const hexOf = (c) => COLORS[c] || "#6366f1";
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Two-letter monogram from a category/tool name (no emoji iconography).
function monogram(name) {
  const words = String(name).replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).filter(Boolean);
  if (!words.length) return "DN";
  if (words.length === 1) return words[0].slice(0, 2).toUpperCase();
  return (words[0][0] + words[1][0]).toUpperCase();
}

const CSS = `
.nx-deck{position:fixed;inset:0;z-index:99999;color:#e5e7eb;font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,system-ui,sans-serif;overflow:hidden;
  background:#070a14;isolation:isolate;-webkit-font-smoothing:antialiased;user-select:none}
.nx-deck *{box-sizing:border-box}
/* aurora background */
.nx-aurora{position:absolute;inset:-20%;z-index:0;filter:blur(60px);opacity:.55;pointer-events:none}
.nx-aurora span{position:absolute;border-radius:50%;mix-blend-mode:screen;animation:nxFloat 22s ease-in-out infinite}
.nx-aurora span:nth-child(1){width:52vw;height:52vw;left:-8vw;top:-10vw;background:#2563eb;animation-delay:0s}
.nx-aurora span:nth-child(2){width:46vw;height:46vw;right:-6vw;top:8vh;background:#7c3aed;animation-delay:-6s}
.nx-aurora span:nth-child(3){width:40vw;height:40vw;left:22vw;bottom:-14vw;background:#06b6d4;animation-delay:-12s}
.nx-aurora span:nth-child(4){width:34vw;height:34vw;right:14vw;bottom:-10vw;background:#ec4899;animation-delay:-18s}
@keyframes nxFloat{0%,100%{transform:translate(0,0) scale(1)}33%{transform:translate(4vw,3vh) scale(1.08)}66%{transform:translate(-3vw,-2vh) scale(.96)}}
.nx-deck::after{content:"";position:absolute;inset:0;z-index:1;pointer-events:none;
  background:radial-gradient(120% 90% at 50% -10%,rgba(255,255,255,.06),transparent 60%);}
/* menubar */
.nx-bar{position:absolute;top:0;left:0;right:0;height:38px;z-index:40;display:flex;align-items:center;gap:14px;padding:0 14px;
  background:rgba(10,14,24,.55);backdrop-filter:blur(22px) saturate(160%);-webkit-backdrop-filter:blur(22px) saturate(160%);
  border-bottom:1px solid rgba(255,255,255,.08)}
.nx-bar .nx-mark{font-weight:700;letter-spacing:.14em;font-size:12px;color:#fff}
.nx-bar .nx-ctx{font-size:12px;color:#94a3b8}
.nx-bar .nx-spot{margin-left:auto;display:flex;align-items:center;gap:8px;height:24px;padding:0 10px;border-radius:7px;cursor:text;
  background:rgba(255,255,255,.08);border:1px solid rgba(255,255,255,.1);color:#cbd5e1;font-size:12px;min-width:200px}
.nx-bar .nx-spot kbd{margin-left:auto;font:11px ui-monospace,monospace;color:#64748b;background:rgba(255,255,255,.06);padding:1px 5px;border-radius:4px}
.nx-bar .nx-clock{font:12px ui-monospace,SFMono-Regular,monospace;color:#cbd5e1;min-width:84px;text-align:right}
.nx-bar .nx-exit{height:24px;padding:0 10px;border-radius:7px;border:1px solid rgba(255,255,255,.14);background:rgba(239,68,68,.16);color:#fecaca;font-size:12px;cursor:pointer}
.nx-bar .nx-exit:hover{background:rgba(239,68,68,.28)}
/* stage */
.nx-stage{position:absolute;inset:38px 0 96px;z-index:10;overflow:hidden}
/* launchpad */
.nx-pad{position:absolute;inset:0;z-index:10;display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:18px;
  padding:34px 48px;align-content:start;overflow:auto;transition:opacity .25s,transform .25s}
.nx-pad.hide{opacity:0;transform:scale(1.04);pointer-events:none}
.nx-pod{position:relative;display:flex;flex-direction:column;align-items:center;gap:10px;padding:18px 10px 14px;border-radius:18px;cursor:pointer;
  background:rgba(255,255,255,.045);border:1px solid rgba(255,255,255,.08);transition:transform .16s,background .16s,border-color .16s}
.nx-pod:hover{transform:translateY(-4px);background:rgba(255,255,255,.09);border-color:rgba(255,255,255,.18)}
.nx-tile{position:relative;width:64px;height:64px;border-radius:16px;display:grid;place-items:center;font-weight:700;font-size:20px;color:#fff;letter-spacing:.02em;
  box-shadow:0 10px 26px rgba(0,0,0,.4),inset 0 1px 0 rgba(255,255,255,.3)}
.nx-tile::after{content:"";position:absolute;inset:0;border-radius:16px;background:linear-gradient(160deg,rgba(255,255,255,.35),transparent 55%)}
.nx-pod .nx-nm{font-size:13px;font-weight:600;color:#e5e7eb;text-align:center;line-height:1.25}
.nx-pod .nx-ct{font-size:11px;color:#94a3b8}
.nx-pod .nx-fan{position:absolute;top:14px;right:14px;left:14px;height:64px;pointer-events:none}
.nx-pod .nx-fan i{position:absolute;left:50%;top:0;width:52px;height:52px;border-radius:13px;opacity:.5;
  transform-origin:bottom center;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.14)}
/* stack popover (Downloads-style fan) */
.nx-stack{position:absolute;z-index:30;max-width:min(680px,86vw);max-height:62vh;overflow:auto;padding:14px;border-radius:18px;
  background:rgba(14,19,32,.82);backdrop-filter:blur(26px) saturate(160%);-webkit-backdrop-filter:blur(26px) saturate(160%);
  border:1px solid rgba(255,255,255,.14);box-shadow:0 24px 70px rgba(0,0,0,.6);
  display:grid;grid-template-columns:repeat(auto-fill,minmax(132px,1fr));gap:10px;animation:nxStack .22s cubic-bezier(.2,.9,.3,1.3)}
@keyframes nxStack{from{opacity:0;transform:translateY(14px) scale(.9)}to{opacity:1;transform:none}}
.nx-stack .nx-sh{grid-column:1/-1;display:flex;align-items:center;gap:8px;font-size:12px;color:#94a3b8;letter-spacing:.08em;text-transform:uppercase;margin-bottom:2px}
.nx-chip{display:flex;align-items:center;gap:9px;padding:9px 10px;border-radius:11px;cursor:pointer;background:rgba(255,255,255,.05);border:1px solid rgba(255,255,255,.08);transition:background .14s,transform .14s}
.nx-chip:hover{background:rgba(255,255,255,.12);transform:translateY(-2px)}
.nx-chip .nx-mn{flex:none;width:30px;height:30px;border-radius:8px;display:grid;place-items:center;font-size:12px;font-weight:700;color:#fff}
.nx-chip .nx-cl{font-size:12.5px;color:#e5e7eb;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nx-chip .nx-lv{flex:none;width:6px;height:6px;border-radius:50%;background:#22c55e;box-shadow:0 0 8px #22c55e}
/* windows */
.nx-win{position:absolute;z-index:20;min-width:300px;width:440px;border-radius:14px;overflow:hidden;
  background:rgba(17,23,38,.88);backdrop-filter:blur(26px) saturate(150%);-webkit-backdrop-filter:blur(26px) saturate(150%);
  border:1px solid rgba(255,255,255,.14);box-shadow:0 30px 80px rgba(0,0,0,.6);animation:nxOpen .2s cubic-bezier(.2,.9,.3,1.25)}
@keyframes nxOpen{from{opacity:0;transform:scale(.92)}to{opacity:1;transform:none}}
.nx-win.max{inset:48px 24px 108px!important;width:auto!important}
.nx-tt{display:flex;align-items:center;gap:10px;height:40px;padding:0 12px;cursor:grab;background:rgba(255,255,255,.05);border-bottom:1px solid rgba(255,255,255,.08)}
.nx-tt:active{cursor:grabbing}
.nx-lights{display:flex;gap:8px}
.nx-lights b{width:12px;height:12px;border-radius:50%;cursor:pointer;display:block}
.nx-lights .c{background:#ff5f57}.nx-lights .m{background:#febc2e}.nx-lights .z{background:#28c840}
.nx-tt .nx-wt{font-size:12.5px;font-weight:600;color:#e5e7eb;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.nx-tt .nx-wg{margin-left:auto;font-size:11px;color:#94a3b8}
.nx-wb{padding:18px;max-height:60vh;overflow:auto}
.nx-wb .nx-big{width:56px;height:56px;border-radius:14px;display:grid;place-items:center;font-weight:700;font-size:18px;color:#fff;margin-bottom:12px}
.nx-wb h3{margin:0 0 4px;font-size:16px;color:#fff}
.nx-wb p{margin:0 0 16px;font-size:13px;color:#94a3b8}
.nx-wb .nx-act{display:flex;gap:10px;flex-wrap:wrap}
.nx-btn{padding:8px 14px;border-radius:9px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.08);color:#e5e7eb;font-size:13px;cursor:pointer}
.nx-btn.pri{background:linear-gradient(180deg,#3b82f6,#2563eb);border-color:#2563eb;color:#fff}
.nx-btn:hover{filter:brightness(1.12)}
/* dock */
.nx-dock{position:absolute;left:50%;bottom:18px;transform:translateX(-50%);z-index:50;display:flex;align-items:flex-end;gap:10px;padding:10px 14px;border-radius:20px;
  background:rgba(14,19,32,.55);backdrop-filter:blur(26px) saturate(160%);-webkit-backdrop-filter:blur(26px) saturate(160%);
  border:1px solid rgba(255,255,255,.12);box-shadow:0 18px 50px rgba(0,0,0,.5);max-width:94vw;overflow-x:auto}
.nx-di{position:relative;flex:none;width:46px;height:46px;border-radius:13px;display:grid;place-items:center;font-weight:700;font-size:15px;color:#fff;cursor:pointer;
  transition:transform .14s;box-shadow:inset 0 1px 0 rgba(255,255,255,.3)}
.nx-di:hover{transform:translateY(-8px) scale(1.12)}
.nx-di[data-home]{background:linear-gradient(160deg,#334155,#0f172a)}
.nx-grid{display:grid;grid-template-columns:1fr 1fr;grid-template-rows:1fr 1fr;gap:4px;width:20px;height:20px}
.nx-grid i{background:rgba(255,255,255,.9);border-radius:3px;display:block}
.nx-di .nx-tip{position:absolute;bottom:56px;left:50%;transform:translateX(-50%);white-space:nowrap;font-size:11px;padding:3px 8px;border-radius:6px;background:rgba(0,0,0,.8);color:#e5e7eb;opacity:0;transition:opacity .12s;pointer-events:none}
.nx-di:hover .nx-tip{opacity:1}
.nx-di.min{width:38px;height:38px;font-size:12px;background:rgba(255,255,255,.1);border:1px solid rgba(255,255,255,.16)}
.nx-dock .nx-sep{flex:none;width:1px;align-self:stretch;margin:4px 2px;background:rgba(255,255,255,.14)}
/* spotlight */
.nx-spotlight{position:absolute;inset:0;z-index:80;display:none;align-items:flex-start;justify-content:center;padding-top:16vh;background:rgba(3,6,14,.5)}
.nx-spotlight.on{display:flex}
.nx-sbox{width:min(600px,90vw);border-radius:16px;overflow:hidden;background:rgba(17,23,38,.9);backdrop-filter:blur(30px) saturate(160%);-webkit-backdrop-filter:blur(30px) saturate(160%);border:1px solid rgba(255,255,255,.16);box-shadow:0 30px 90px rgba(0,0,0,.7)}
.nx-sbox input{width:100%;border:0;outline:0;background:transparent;color:#fff;font-size:20px;padding:18px 20px;border-bottom:1px solid rgba(255,255,255,.1)}
.nx-sres{max-height:46vh;overflow:auto;padding:6px}
.nx-sr{display:flex;align-items:center;gap:11px;padding:9px 12px;border-radius:10px;cursor:pointer}
.nx-sr.sel,.nx-sr:hover{background:rgba(59,130,246,.22)}
.nx-sr .nx-mn{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;font-size:11px;font-weight:700;color:#fff;flex:none}
.nx-sr .nx-rl{font-size:13.5px;color:#e5e7eb}
.nx-sr .nx-rg{margin-left:auto;font-size:11px;color:#64748b}
.nx-empty{padding:22px;text-align:center;color:#64748b;font-size:13px}
`;

export function renderDeck(host, opts) {
  opts = opts || {};
  const groups = (opts.groups || []).filter((g) => g.items && g.items.length);
  const onOpen = typeof opts.onOpen === "function" ? opts.onOpen : () => {};
  const onExit = typeof opts.onExit === "function" ? opts.onExit : () => {};

  // flat index for spotlight
  const index = [];
  for (const g of groups) for (const it of g.items) index.push({ sec: it.sec, label: it.label, group: g.name, color: g.color, badge: it.badge });

  if (!document.getElementById("nx-deck-css")) {
    const st = document.createElement("style"); st.id = "nx-deck-css"; st.textContent = CSS; document.head.appendChild(st);
  }

  const root = document.createElement("div");
  root.className = "nx-deck";
  root.innerHTML = `
    <div class="nx-aurora"><span></span><span></span><span></span><span></span></div>
    <div class="nx-bar">
      <span class="nx-mark">DARKNODE</span>
      <span class="nx-ctx" id="nxCtx">Deck</span>
      <div class="nx-spot" id="nxSpotBtn">Search tools and categories<kbd>Ctrl K</kbd></div>
      <span class="nx-clock" id="nxClock"></span>
      <button class="nx-exit" id="nxExit">Exit preview</button>
    </div>
    <div class="nx-stage" id="nxStage">
      <div class="nx-pad" id="nxPad"></div>
    </div>
    <div class="nx-dock" id="nxDock"></div>
    <div class="nx-spotlight" id="nxSpot">
      <div class="nx-sbox">
        <input id="nxSpotIn" placeholder="Jump to any tool…" autocomplete="off" spellcheck="false">
        <div class="nx-sres" id="nxSpotRes"></div>
      </div>
    </div>`;
  (host || document.body).appendChild(root);

  const $ = (s) => root.querySelector(s);
  const pad = $("#nxPad"), dock = $("#nxDock"), stage = $("#nxStage"), ctx = $("#nxCtx");
  let zTop = 30, winN = 0, stackEl = null;
  const mins = new Map(); // minimized windows: id -> {win, label}

  // ---- clock ----
  const clock = $("#nxClock");
  const tick = () => { const d = new Date(); clock.textContent = d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); };
  tick(); const clockId = setInterval(tick, 10000);

  // ---- launchpad pods ----
  function tile(name, color, cls) {
    const h = hexOf(color);
    return `<div class="${cls}" style="background:linear-gradient(160deg,${h},${shade(h,-28)})">${esc(monogram(name))}</div>`;
  }
  pad.innerHTML = groups.map((g, i) => `
    <div class="nx-pod" data-g="${i}">
      ${tile(g.name, g.color, "nx-tile")}
      <div class="nx-nm">${esc(g.name)}</div>
      <div class="nx-ct">${g.items.length} tool${g.items.length === 1 ? "" : "s"}</div>
    </div>`).join("");

  pad.querySelectorAll(".nx-pod").forEach((pod) => {
    pod.addEventListener("click", (e) => { e.stopPropagation(); openStack(groups[+pod.dataset.g], pod); });
  });

  // ---- Downloads-style stack fan-out ----
  function closeStack() { if (stackEl) { stackEl.remove(); stackEl = null; } }
  function openStack(g, anchor) {
    closeStack();
    const h = hexOf(g.color);
    stackEl = document.createElement("div");
    stackEl.className = "nx-stack";
    stackEl.innerHTML = `<div class="nx-sh"><span style="width:8px;height:8px;border-radius:50%;background:${h};display:inline-block"></span>${esc(g.name)}</div>` +
      g.items.map((it) => `
        <div class="nx-chip" data-sec="${esc(it.sec)}" data-label="${esc(it.label)}">
          <span class="nx-mn" style="background:linear-gradient(160deg,${h},${shade(h,-28)})">${esc(monogram(it.label))}</span>
          <span class="nx-cl">${esc(it.label)}</span>
          ${it.badge === "live" ? '<span class="nx-lv"></span>' : ""}
        </div>`).join("");
    stage.appendChild(stackEl);
    // position above the dock, centered under the pod when possible
    const r = anchor.getBoundingClientRect(), sr = stage.getBoundingClientRect();
    stackEl.style.left = Math.max(12, Math.min(r.left - sr.left + r.width / 2 - stackEl.offsetWidth / 2, sr.width - stackEl.offsetWidth - 12)) + "px";
    stackEl.style.top = Math.max(12, Math.min(r.top - sr.top + r.height, sr.height - stackEl.offsetHeight - 12)) + "px";
    stackEl.querySelectorAll(".nx-chip").forEach((c) => c.addEventListener("click", (e) => { e.stopPropagation(); openWindow(c.dataset.sec, c.dataset.label, g); closeStack(); }));
  }
  stage.addEventListener("click", closeStack);

  // ---- tool windows (draggable, traffic lights) ----
  function openWindow(sec, label, g) {
    const h = hexOf(g ? g.color : "blue");
    const id = "w" + (++winN);
    const win = document.createElement("div");
    win.className = "nx-win"; win.style.zIndex = ++zTop;
    win.style.left = (60 + (winN % 6) * 28) + "px"; win.style.top = (26 + (winN % 6) * 24) + "px";
    win.innerHTML = `
      <div class="nx-tt">
        <span class="nx-lights"><b class="c" title="Close"></b><b class="m" title="Minimize"></b><b class="z" title="Zoom"></b></span>
        <span class="nx-wt">${esc(label)}</span>
        <span class="nx-wg">${esc(g ? g.name : "")}</span>
      </div>
      <div class="nx-wb">
        ${tile(label, g ? g.color : "blue", "nx-big")}
        <h3>${esc(label)}</h3>
        <p>Part of <strong>${esc(g ? g.name : "Darknode")}</strong>. Launch it in the console, or keep it floating here on the deck.</p>
        <div class="nx-act">
          <button class="nx-btn pri" data-open="${esc(sec)}">Open in console</button>
          <button class="nx-btn" data-min>Minimize</button>
        </div>
      </div>`;
    stage.appendChild(win);
    ctx.textContent = label;
    win.addEventListener("mousedown", () => { win.style.zIndex = ++zTop; }, true);
    const tt = win.querySelector(".nx-tt");
    dragify(win, tt);
    tt.querySelector(".c").addEventListener("click", () => { win.remove(); mins.delete(id); drawDock(); });
    tt.querySelector(".m").addEventListener("click", () => minimize(id, win, label, h));
    tt.querySelector(".z").addEventListener("click", () => win.classList.toggle("max"));
    win.querySelector("[data-min]").addEventListener("click", () => minimize(id, win, label, h));
    win.querySelector("[data-open]").addEventListener("click", () => { teardown(); onOpen(sec); });
    return win;
  }
  function minimize(id, win, label, h) { win.style.display = "none"; mins.set(id, { win, label, h }); drawDock(); }

  // drag by a handle
  function dragify(win, handle) {
    let sx, sy, ox, oy, on = false;
    handle.addEventListener("mousedown", (e) => {
      if (e.target.closest(".nx-lights")) return;
      on = true; sx = e.clientX; sy = e.clientY; const r = win.getBoundingClientRect(); ox = r.left; oy = r.top; win.classList.remove("max"); e.preventDefault();
      const mv = (ev) => { if (!on) return; win.style.left = (ox + ev.clientX - sx) + "px"; win.style.top = Math.max(40, oy + ev.clientY - sy) + "px"; };
      const up = () => { on = false; document.removeEventListener("mousemove", mv); document.removeEventListener("mouseup", up); };
      document.addEventListener("mousemove", mv); document.addEventListener("mouseup", up);
    });
  }

  // ---- dock: category shortcuts + minimized tray ----
  function drawDock() {
    const cats = groups.slice(0, 11);
    dock.innerHTML = `<div class="nx-di" data-home title="Launchpad"><span class="nx-grid"><i></i><i></i><i></i><i></i></span><span class="nx-tip">Launchpad</span></div><div class="nx-sep"></div>` +
      cats.map((g, i) => { const h = hexOf(g.color); return `<div class="nx-di" data-g="${i}" style="background:linear-gradient(160deg,${h},${shade(h,-28)})">${esc(monogram(g.name))}<span class="nx-tip">${esc(g.name)}</span></div>`; }).join("");
    if (mins.size) {
      dock.innerHTML += `<div class="nx-sep"></div>` + [...mins.entries()].map(([id, m]) => `<div class="nx-di min" data-restore="${id}" style="box-shadow:inset 0 0 0 1px ${m.h}">${esc(monogram(m.label))}<span class="nx-tip">${esc(m.label)}</span></div>`).join("");
    }
    dock.querySelector("[data-home]").addEventListener("click", () => { closeAllStacks(); pad.classList.remove("hide"); });
    dock.querySelectorAll("[data-g]").forEach((d) => d.addEventListener("click", () => { const pod = pad.querySelector(`.nx-pod[data-g="${d.dataset.g}"]`); pad.classList.remove("hide"); openStack(groups[+d.dataset.g], pod || dock); }));
    dock.querySelectorAll("[data-restore]").forEach((d) => d.addEventListener("click", () => { const m = mins.get(d.dataset.restore); if (m) { m.win.style.display = ""; m.win.style.zIndex = ++zTop; mins.delete(d.dataset.restore); drawDock(); } }));
  }
  function closeAllStacks() { closeStack(); }
  drawDock();

  // ---- spotlight ----
  const spot = $("#nxSpot"), spotIn = $("#nxSpotIn"), spotRes = $("#nxSpotRes");
  let selIdx = 0, matches = [];
  function openSpot() { spot.classList.add("on"); spotIn.value = ""; runSpot(""); spotIn.focus(); }
  function closeSpot() { spot.classList.remove("on"); }
  function runSpot(q) {
    q = q.trim().toLowerCase();
    matches = (q ? index.filter((t) => t.label.toLowerCase().includes(q) || t.group.toLowerCase().includes(q)) : index).slice(0, 60);
    selIdx = 0;
    spotRes.innerHTML = matches.length ? matches.map((t, i) => { const h = hexOf(t.color); return `
      <div class="nx-sr${i === 0 ? " sel" : ""}" data-i="${i}">
        <span class="nx-mn" style="background:linear-gradient(160deg,${h},${shade(h,-28)})">${esc(monogram(t.label))}</span>
        <span class="nx-rl">${esc(t.label)}</span><span class="nx-rg">${esc(t.group)}</span>
      </div>`; }).join("") : `<div class="nx-empty">No tool matches "${esc(q)}"</div>`;
    spotRes.querySelectorAll(".nx-sr").forEach((r) => r.addEventListener("click", () => chooseSpot(+r.dataset.i)));
  }
  function chooseSpot(i) { const t = matches[i]; if (!t) return; teardown(); onOpen(t.sec); }
  function moveSel(d) { if (!matches.length) return; selIdx = (selIdx + d + matches.length) % matches.length; spotRes.querySelectorAll(".nx-sr").forEach((r, i) => r.classList.toggle("sel", i === selIdx)); const el = spotRes.querySelector(".nx-sr.sel"); if (el) el.scrollIntoView({ block: "nearest" }); }
  $("#nxSpotBtn").addEventListener("click", openSpot);
  spotIn.addEventListener("input", () => runSpot(spotIn.value));

  // ---- keyboard ----
  function onKey(e) {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); spot.classList.contains("on") ? closeSpot() : openSpot(); return; }
    if (spot.classList.contains("on")) {
      if (e.key === "Escape") { e.preventDefault(); closeSpot(); }
      else if (e.key === "ArrowDown") { e.preventDefault(); moveSel(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); moveSel(-1); }
      else if (e.key === "Enter") { e.preventDefault(); chooseSpot(selIdx); }
      return;
    }
    if (e.key === "Escape") {
      if (stackEl) { closeStack(); return; }
      const wins = [...stage.querySelectorAll(".nx-win")].filter((w) => w.style.display !== "none");
      if (wins.length) { wins.sort((a, b) => (+b.style.zIndex) - (+a.style.zIndex))[0].remove(); drawDock(); return; }
      teardown(); onExit();
    }
  }
  document.addEventListener("keydown", onKey);
  $("#nxExit").addEventListener("click", () => { teardown(); onExit(); });
  spot.addEventListener("click", (e) => { if (e.target === spot) closeSpot(); });

  function teardown() {
    clearInterval(clockId);
    document.removeEventListener("keydown", onKey);
    root.remove();
  }
  return teardown;
}

// darken/lighten a hex color by pct (-100..100) for subtle tile gradients
function shade(hex, pct) {
  const n = parseInt(hex.slice(1), 16);
  let r = (n >> 16) & 255, g = (n >> 8) & 255, b = n & 255;
  const f = pct / 100;
  r = Math.round(r + (f < 0 ? r : 255 - r) * f);
  g = Math.round(g + (f < 0 ? g : 255 - g) * f);
  b = Math.round(b + (f < 0 ? b : 255 - b) * f);
  return "#" + ((1 << 24) + (r << 16) + (g << 8) + b).toString(16).slice(1);
}
