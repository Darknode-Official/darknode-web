// Toast notification system
const COLORS = { info: "#2563eb", success: "#16a34a", error: "#dc2626", warning: "#d97706" };
let container;

function ensureContainer() {
  if (container && document.body.contains(container)) return;
  container = document.createElement("div");
  container.className = "toast-stack";
  Object.assign(container.style, {
    position: "fixed", top: "72px", right: "20px", zIndex: "9999",
    display: "flex", flexDirection: "column", alignItems: "flex-end", gap: "8px", pointerEvents: "none", maxWidth: "380px"
  });
  document.body.appendChild(container);
}

function ensureStyles() {
  if (document.getElementById("toast-css")) return;
  const s = document.createElement("style");
  s.id = "toast-css";
  s.textContent = `
    .toast-item{pointer-events:auto;display:flex;align-items:flex-start;gap:10px;padding:12px 16px;max-width:380px;width:auto;
      border-radius:8px;border-left:4px solid var(--toast-c);background:#1e1e1e;color:#e4e4e4;
      box-shadow:0 8px 24px rgba(0,0,0,.25);font-size:.82rem;line-height:1.5;cursor:pointer;position:relative;overflow:hidden;
      animation:toastIn .3s cubic-bezier(.4,0,.2,1)}
    .toast-item.bump{animation:toastBump .35s cubic-bezier(.4,0,.2,1)}
    .toast-item.out{animation:toastOut .25s cubic-bezier(.4,0,.2,1) forwards}
    .toast-bar{position:absolute;bottom:0;left:0;height:2px;background:var(--toast-c);opacity:.5;border-radius:0 0 0 4px}
    .toast-label{font-weight:600;text-transform:uppercase;font-size:.68rem;letter-spacing:.04em;color:var(--toast-c);margin-bottom:2px}
    .toast-msg{flex:1}
    .toast-x{background:none;border:none;color:#888;cursor:pointer;font-size:.9rem;padding:2px 4px;line-height:1;flex-shrink:0}
    .toast-x:hover{color:#fff}
    [data-style=pro] .toast-item{background:#fff;color:#0f172a;box-shadow:0 4px 16px rgba(0,0,0,.08)}
    [data-style=pro] .toast-x:hover{color:#0f172a}
    [data-style=dark] .toast-item{background:#1e293b;border-color:var(--toast-c)}
    @keyframes toastIn{from{opacity:0;transform:translateX(30px)}to{opacity:1;transform:translateX(0)}}
    @keyframes toastOut{to{opacity:0;transform:translateX(30px)}}
    @keyframes toastBump{0%{transform:scale(1)}35%{transform:scale(1.04)}100%{transform:scale(1)}}
    @media(max-width:480px){.toast-stack{right:8px;left:8px;max-width:none}}`;
  document.head.appendChild(s);
}

const MAX_TOASTS = 4;

export function showToast(message, type = "info", duration = 4000) {
  ensureStyles();
  ensureContainer();

  // De-dupe: if an identical toast is already showing (e.g. spamming the
  // density toggle), just refresh it with a little bump instead of stacking.
  const key = type + "\u0000" + message;
  const existing = [...container.children].find((n) => n.dataset && n.dataset.key === key && !n.classList.contains("out"));
  if (existing) {
    existing.classList.remove("bump");
    void existing.offsetWidth; // restart the animation
    existing.classList.add("bump");
    const bar = existing.querySelector(".toast-bar");
    if (bar) { bar.style.transition = "none"; bar.style.width = "100%"; requestAnimationFrame(() => { bar.style.transition = `width ${duration}ms linear`; bar.style.width = "0%"; }); }
    if (existing._t) clearTimeout(existing._t);
    existing._t = setTimeout(existing._dismiss, duration);
    return;
  }

  // Cap the stack so it never runs off the screen.
  while (container.children.length >= MAX_TOASTS) container.firstElementChild.remove();

  const c = COLORS[type] || COLORS.info;
  const el = document.createElement("div");
  el.className = "toast-item";
  el.dataset.key = key;
  el.style.setProperty("--toast-c", c);
  el.innerHTML = `<div class="toast-msg"><div class="toast-label">${type}</div>${message}</div><button class="toast-x" aria-label="Dismiss">x</button><div class="toast-bar" style="width:100%;transition:width ${duration}ms linear"></div>`;
  container.appendChild(el);
  requestAnimationFrame(() => {
    const bar = el.querySelector(".toast-bar");
    if (bar) bar.style.width = "0%";
  });
  const dismiss = () => {
    if (el._t) clearTimeout(el._t);
    el.classList.add("out");
    el.addEventListener("animationend", () => el.remove());
  };
  el._dismiss = dismiss;
  el.querySelector(".toast-x").addEventListener("click", (e) => { e.stopPropagation(); dismiss(); });
  el.addEventListener("click", dismiss);
  el._t = setTimeout(dismiss, duration);
}
