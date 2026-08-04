// Game-style guided walkthrough: dims the whole page, spotlights one element at a
// time with a callout, and a Skip button. Blocks page interaction while active.
const DONE_KEY = "sentinel_tour_done";
export function tourDone() { return localStorage.getItem(DONE_KEY) === "1"; }

export function startTour(steps) {
  const overlay = document.createElement("div"); overlay.className = "tour-overlay";
  const hole = document.createElement("div"); hole.className = "tour-hole";
  const callout = document.createElement("div"); callout.className = "tour-callout";
  overlay.appendChild(hole); overlay.appendChild(callout);
  document.body.appendChild(overlay);

  let idx = 0;
  const has = (i) => { const s = steps[i]; return s && (!s.sel || document.querySelector(s.sel)); };
  const seek = (from, dir) => { let i = from; while (i >= 0 && i < steps.length) { if (has(i)) return i; i += dir; } return -1; };

  function end() {
    overlay.remove();
    window.removeEventListener("resize", reposition);
    window.removeEventListener("scroll", reposition, true);
    localStorage.setItem(DONE_KEY, "1");
  }

  function reposition() {
    const s = steps[idx];
    const target = s.sel ? document.querySelector(s.sel) : null;
    if (target) {
      const r = target.getBoundingClientRect(), pad = 8;
      hole.style.display = "block";
      hole.style.left = (r.left - pad) + "px"; hole.style.top = (r.top - pad) + "px";
      hole.style.width = (r.width + pad * 2) + "px"; hole.style.height = (r.height + pad * 2) + "px";
      callout.style.transform = "";
      const co = callout.getBoundingClientRect();
      const below = r.bottom + co.height + 20 < window.innerHeight;
      callout.style.top = (below ? r.bottom + 14 : Math.max(12, r.top - co.height - 14)) + "px";
      callout.style.left = Math.min(Math.max(12, r.left), Math.max(12, window.innerWidth - co.width - 12)) + "px";
    } else {
      hole.style.display = "none";
      callout.style.left = "50%"; callout.style.top = "50%"; callout.style.transform = "translate(-50%,-50%)";
    }
  }

  function render() {
    const s = steps[idx];
    const last = seek(idx + 1, 1) === -1;
    const first = seek(idx - 1, -1) === -1;
    callout.innerHTML = `
      <div class="tour-step">${idx + 1} / ${steps.length}</div>
      <div class="tour-title">${s.title || ""}</div>
      <div class="tour-text">${s.text || ""}</div>
      <div class="tour-actions">
        <button class="tour-skip" data-a="skip">Skip walkthrough</button>
        <span style="flex:1"></span>
        ${first ? "" : `<button class="btn ghost" data-a="back">Back</button>`}
        <button class="btn" data-a="next">${last ? "Done" : "Next"}</button>
      </div>`;
    const target = s.sel ? document.querySelector(s.sel) : null;
    if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
    setTimeout(reposition, 280);
  }

  callout.addEventListener("click", (ev) => {
    const b = ev.target.closest("[data-a]"); if (!b) return;
    const a = b.dataset.a;
    if (a === "skip") return end();
    if (a === "back") { const p = seek(idx - 1, -1); if (p >= 0) { idx = p; render(); } return; }
    if (a === "next") { const n = seek(idx + 1, 1); if (n < 0) end(); else { idx = n; render(); } }
  });
  window.addEventListener("resize", reposition);
  window.addEventListener("scroll", reposition, true);

  idx = seek(0, 1);
  if (idx < 0) return end();
  render();
}
