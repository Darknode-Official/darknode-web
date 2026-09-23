// Scroll-to-top button — auto-initializes on import
(function () {
  const s = document.createElement("style");
  s.textContent = `
    .stt{position:fixed;bottom:24px;right:24px;z-index:90;width:44px;height:44px;border-radius:var(--btn-radius,4px);
      border:none;cursor:pointer;display:flex;align-items:center;justify-content:center;
      background:#18181b;color:#fff;box-shadow:0 4px 14px rgba(0,0,0,.18);
      opacity:0;pointer-events:none;transform:translateY(12px);
      transition:opacity .25s cubic-bezier(.4,0,.2,1),transform .25s cubic-bezier(.4,0,.2,1),background .15s,box-shadow .15s}
    .stt.show{opacity:1;pointer-events:auto;transform:translateY(0)}
    .stt:hover{background:#3f3f46;box-shadow:0 6px 20px rgba(0,0,0,.25)}
    .stt:active{transform:translateY(0) scale(.92)}
    [data-style=pro] .stt{background:#fff;color:#18181b;border:1px solid #e2e8f0;box-shadow:0 2px 8px rgba(0,0,0,.06)}
    [data-style=pro] .stt:hover{background:#f8fafc;border-color:#cbd5e1;box-shadow:0 4px 14px rgba(37,99,235,.1)}
    [data-style=dark] .stt{background:#1e293b;border:1px solid #334155}
    [data-style=dark] .stt:hover{background:#334155}
    @media(max-width:640px){.stt{bottom:16px;right:16px;width:48px;height:48px}}`;
  document.head.appendChild(s);

  const btn = document.createElement("button");
  btn.className = "stt";
  btn.setAttribute("aria-label", "Scroll to top");
  btn.innerHTML = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><path d="M18 15l-6-6-6 6"/></svg>';
  document.body.appendChild(btn);

  let ticking = false;
  const check = () => {
    btn.classList.toggle("show", window.scrollY > 400);
    ticking = false;
  };
  window.addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(check); } }, { passive: true });
  btn.addEventListener("click", () => window.scrollTo({ top: 0, behavior: "smooth" }));
  check();
})();
