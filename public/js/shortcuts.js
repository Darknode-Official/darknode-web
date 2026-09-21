// Keyboard shortcuts overlay — auto-initializes on import
(function () {
  const mac = navigator.platform.indexOf("Mac") > -1;
  const mod = mac ? "Cmd" : "Ctrl";
  const shortcuts = [
    [mod + "+K", "Command palette"],
    ["Shift+?", "Keyboard shortcuts"],
    ["Esc", "Close overlays"],
    ["G then H", "Go to Dashboard"],
    ["G then T", "Go to Tools"],
    ["G then A", "Go to AI"],
    ["G then S", "Go to Settings"],
  ];

  const s = document.createElement("style");
  s.textContent = `
    .kb-overlay{position:fixed;inset:0;z-index:999;background:rgba(0,0,0,.55);backdrop-filter:blur(4px);
      display:flex;align-items:center;justify-content:center;opacity:0;pointer-events:none;transition:opacity .2s}
    .kb-overlay.open{opacity:1;pointer-events:auto}
    .kb-modal{background:#1e1e1e;border:1px solid #333;border-radius:12px;padding:28px 32px;min-width:340px;max-width:440px;
      color:#e4e4e4;box-shadow:0 16px 48px rgba(0,0,0,.4);transform:scale(.96);transition:transform .2s cubic-bezier(.4,0,.2,1)}
    .kb-overlay.open .kb-modal{transform:scale(1)}
    .kb-title{font-size:1rem;font-weight:700;margin:0 0 20px;letter-spacing:-.01em}
    .kb-row{display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid #2a2a2a}
    .kb-row:last-child{border-bottom:none}
    .kb-desc{font-size:.82rem;color:#aaa}
    .kb-key{display:inline-flex;gap:4px}
    .kb-key kbd{font-family:ui-monospace,monospace;font-size:.72rem;padding:3px 7px;border-radius:5px;
      background:#2a2a2a;border:1px solid #3a3a3a;color:#ccc;line-height:1.3;white-space:nowrap}
    .kb-close{position:absolute;top:12px;right:14px;background:none;border:none;color:#888;cursor:pointer;font-size:1.1rem;padding:4px}
    .kb-close:hover{color:#fff}
    [data-style=pro] .kb-modal{background:#fff;border-color:#e2e8f0;color:#0f172a;box-shadow:0 16px 48px rgba(0,0,0,.12)}
    [data-style=pro] .kb-row{border-bottom-color:#f1f5f9}
    [data-style=pro] .kb-desc{color:#64748b}
    [data-style=pro] .kb-key kbd{background:#f1f5f9;border-color:#e2e8f0;color:#334155}
    [data-style=pro] .kb-close{color:#94a3b8}
    [data-style=pro] .kb-close:hover{color:#0f172a}
    [data-style=dark] .kb-modal{background:#1e293b;border-color:#334155}
    [data-style=dark] .kb-row{border-bottom-color:#283a5a}
    [data-style=dark] .kb-key kbd{background:#0f172a;border-color:#334155;color:#94a3b8}`;
  document.head.appendChild(s);

  let overlay = null;
  function build() {
    overlay = document.createElement("div");
    overlay.className = "kb-overlay";
    overlay.innerHTML = `<div class="kb-modal" style="position:relative">
      <button class="kb-close" aria-label="Close">x</button>
      <div class="kb-title">Keyboard Shortcuts</div>
      ${shortcuts.map(([k, d]) => `<div class="kb-row"><span class="kb-desc">${d}</span><span class="kb-key">${k.split("+").map(p => `<kbd>${p}</kbd>`).join("")}</span></div>`).join("")}
    </div>`;
    document.body.appendChild(overlay);
    overlay.addEventListener("click", (e) => { if (e.target === overlay || e.target.closest(".kb-close")) close(); });
  }
  function open() { if (!overlay) build(); requestAnimationFrame(() => overlay.classList.add("open")); }
  function close() { if (overlay) overlay.classList.remove("open"); }

  let gPending = false, gTimer;
  document.addEventListener("keydown", (e) => {
    if (e.target.tagName === "INPUT" || e.target.tagName === "TEXTAREA" || e.target.isContentEditable) return;
    if (e.key === "Escape" && overlay && overlay.classList.contains("open")) { close(); e.preventDefault(); return; }
    if ((e.key === "?" && e.shiftKey) || (e.key === "/" && (e.ctrlKey || e.metaKey))) { e.preventDefault(); open(); return; }
    if (e.key === "g" || e.key === "G") { if (!gPending) { gPending = true; gTimer = setTimeout(() => { gPending = false; }, 800); } return; }
    if (gPending) {
      gPending = false; clearTimeout(gTimer);
      const map = { h: "home", t: "tools", a: "ai", s: "settings" };
      const sec = map[e.key.toLowerCase()];
      if (sec) { e.preventDefault(); const ev = new CustomEvent("dn:navigate", { detail: sec }); document.dispatchEvent(ev); }
    }
  });
})();
