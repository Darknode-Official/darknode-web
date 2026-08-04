// Interactive tools checklist. Installed tools show as "ready"; clicking one that
// is NOT installed redirects you to its install command in the Downloads section.
import { TOOLS, isInstalled, highlightTool } from "/js/downloads.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

export function renderTools(el) {
  if (!el) return;
  el.innerHTML = TOOLS.map((t) => {
    const done = isInstalled(t.id);
    return `<button class="tool-chip${done ? " installed" : ""}" data-id="${t.id}">
      <span class="tool-dot"></span>${esc(t.name)}
      <span class="tool-state">${done ? "ready" : "install"}</span>
    </button>`;
  }).join("");

  el.onclick = (ev) => {
    const b = ev.target.closest(".tool-chip");
    if (!b) return;
    const id = b.dataset.id;
    if (!isInstalled(id)) {
      highlightTool(id); // jump to the command
    } else {
      const t = TOOLS.find((x) => x.id === id);
      alert(`${t.name} is installed - run it in your terminal.`);
    }
  };

  // Keep chips in sync when install state changes in Downloads.
  document.addEventListener("sentinel:installed-changed", () => renderTools(el), { once: true });
}
