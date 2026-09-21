// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Mobile bottom navigation — auto-initializes on import
(function () {
  if (window.__mnavInit) return;
  window.__mnavInit = true;

  const ITEMS = [
    { sec: "home", label: "Dashboard", icon: '<path d="M2 8l6-6 6 6"/><path d="M4 7v7h3v-4h2v4h3V7"/>' },
    { sec: "tools", label: "Tools", icon: '<path d="M10.3 2.3a1 1 0 0 1 1.4 0l2 2a1 1 0 0 1 0 1.4L6 13.4 2 14l.6-4z"/><path d="M9 4l3 3"/>' },
    { sec: "ai", label: "AI", icon: '<rect x="4" y="4" width="8" height="8" rx="1.5"/><circle cx="6.5" cy="8" r=".8"/><circle cx="9.5" cy="8" r=".8"/><line x1="8" y1="1" x2="8" y2="4"/><line x1="8" y1="12" x2="8" y2="15"/><line x1="1" y1="8" x2="4" y2="8"/><line x1="12" y1="8" x2="15" y2="8"/>' },
    { sec: "_search", label: "Search", icon: '<circle cx="6.5" cy="6.5" r="4.5" fill="none"/><line x1="10" y1="10" x2="14" y2="14"/>' },
    { sec: "settings", label: "Settings", icon: '<circle cx="8" cy="8" r="2.5" fill="none"/><path d="M8 1.5v2M8 12.5v2M1.5 8h2M12.5 8h2M3.1 3.1l1.4 1.4M11.5 11.5l1.4 1.4M3.1 12.9l1.4-1.4M11.5 4.5l1.4-1.4"/>' }
  ];

  const style = document.createElement("style");
  style.textContent = `
.mnav-bar{display:none;position:fixed;bottom:0;left:0;right:0;z-index:200;
  background:var(--bg);border-top:1px solid var(--line);
  padding:4px 0 env(safe-area-inset-bottom,0);justify-content:space-around;align-items:center;
  transition:transform .25s ease}
.mnav-bar.mnav-hidden{transform:translateY(100%)}
.mnav-item{flex:1;background:none;border:none;color:var(--mut);font-size:.6rem;
  padding:6px 4px 4px;cursor:pointer;display:flex;flex-direction:column;align-items:center;gap:2px;
  -webkit-tap-highlight-color:transparent;transition:color .15s ease}
.mnav-item.mnav-active{color:var(--acc)}
.mnav-icon{width:20px;height:20px}
.mnav-icon svg{width:100%;height:100%;stroke:currentColor;stroke-width:1.5;stroke-linecap:round;stroke-linejoin:round;fill:none}
.mnav-label{line-height:1;letter-spacing:.02em}
@media(max-width:720px){.mnav-bar{display:flex}#view{padding-bottom:64px}}
@media(min-width:721px){.mnav-bar{display:none!important}}`;
  document.head.appendChild(style);

  const bar = document.createElement("nav");
  bar.className = "mnav-bar";
  bar.setAttribute("aria-label", "Mobile navigation");
  bar.innerHTML = ITEMS.map(it =>
    `<button class="mnav-item" data-mnav="${it.sec}" aria-label="${it.label}">` +
    `<span class="mnav-icon"><svg viewBox="0 0 16 16">${it.icon}</svg></span>` +
    `<span class="mnav-label">${it.label}</span></button>`
  ).join("");
  document.body.appendChild(bar);

  function setActive(sec) {
    bar.querySelectorAll(".mnav-item").forEach(b => {
      const s = b.dataset.mnav;
      b.classList.toggle("mnav-active", s === sec || (s === "home" && sec === "home"));
    });
  }

  bar.addEventListener("click", (e) => {
    const btn = e.target.closest(".mnav-item");
    if (!btn) return;
    const sec = btn.dataset.mnav;
    if (sec === "_search") {
      document.dispatchEvent(new KeyboardEvent("keydown", { key: "k", ctrlKey: true, bubbles: true }));
      return;
    }
    document.dispatchEvent(new CustomEvent("dn:navigate", { detail: sec }));
    setActive(sec);
  });

  document.addEventListener("dn:navigate", (e) => { if (e.detail) setActive(e.detail); });

  const obs = new MutationObserver(() => {
    const active = document.querySelector(".side-item.active");
    if (active && active.dataset.sec) setActive(active.dataset.sec);
  });
  const tryObserve = () => {
    const nav = document.querySelector(".side-nav");
    if (nav) obs.observe(nav, { subtree: true, attributes: true, attributeFilter: ["class"] });
    else setTimeout(tryObserve, 500);
  };
  tryObserve();

  let lastY = 0;
  const appMain = () => document.querySelector(".app-main") || window;
  const scrollTarget = () => document.querySelector(".app-main") || window;

  function onScroll() {
    const el = scrollTarget();
    const y = el === window ? window.scrollY : el.scrollTop;
    if (y > lastY + 60) bar.classList.add("mnav-hidden");
    else if (y < lastY - 20) bar.classList.remove("mnav-hidden");
    lastY = y;
  }

  window.addEventListener("scroll", onScroll, { passive: true });
  setTimeout(() => {
    const m = document.querySelector(".app-main");
    if (m) m.addEventListener("scroll", onScroll, { passive: true });
  }, 1000);

  setActive("home");
})();
