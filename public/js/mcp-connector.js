// MCP Connector — "Connect to Darknode" interop hub.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Two real integration paths:
//   (a) an MCP (Model Context Protocol) client config that launches `darknode mcp`
//       from darknode-cli on the user's machine, and
//   (b) a link catalog of tool routes with `?embed=1` (framable only by Darknode-origin
//       pages: frame-ancestors 'self').
// This module is a generator/documentation surface only — it makes NO network calls.

import { NAV } from "/js/console-nav.js?v=20261029d";

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// Sections that are not exposable tools (shell/account/privileged surfaces).
const EXCLUDE = new Set(["home", "settings", "admin"]);

// Flatten NAV groups → [{ sec, label, group }], minus excluded sections and dupes.
function flattenTools() {
  const out = [];
  const seen = new Set();
  for (const g of (Array.isArray(NAV) ? NAV : [])) {
    for (const it of (g && Array.isArray(g.items) ? g.items : [])) {
      if (!it || !it.sec || EXCLUDE.has(it.sec) || seen.has(it.sec)) continue;
      seen.add(it.sec);
      out.push({ sec: it.sec, label: it.label || it.sec, group: g.name || "Tools" });
    }
  }
  return out;
}

// Origin computed dynamically; falls back to the production host.
function originOf() {
  try {
    if (location && location.origin && /^https?:/.test(location.origin)) return location.origin;
  } catch (_) {}
  return "https://darknode.ai";
}

const toast = (msg) => { try { if (typeof window.showToast === "function") window.showToast(msg); } catch (_) {} };

function copyText(text, okMsg) {
  const done = () => toast(okMsg || "Copied to clipboard");
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
      return;
    }
  } catch (_) {}
  fallbackCopy(text, done);
}

function fallbackCopy(text, done) {
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    document.body.removeChild(ta);
    done();
  } catch (_) { toast("Copy failed — select the text manually"); }
}

function downloadText(filename, text) {
  try {
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => { try { URL.revokeObjectURL(url); } catch (_) {} }, 2000);
    toast("Downloaded " + filename);
  } catch (_) { toast("Download failed"); }
}

// Short, honest description line per tool for the generated catalog.
function describe(t) {
  return t.label + " (" + t.group + "). Opens at /" + t.sec + "; add ?embed=1 to hide the Deck chrome.";
}

const MCPC_CSS = `<style>
.mcpc-wrap{max-width:none}
.mcpc-grid{display:grid;grid-template-columns:minmax(280px,360px) 1fr;gap:16px;align-items:start}
@media(max-width:860px){.mcpc-grid{grid-template-columns:1fr}}
.mcpc-note{font-size:.82rem;line-height:1.6;color:var(--txt-2,var(--mut))}
.mcpc-note strong{color:var(--txt)}
.mcpc-note code{font-family:var(--font-mono);background:var(--card2);border:1px solid var(--line);border-radius:4px;padding:1px 5px;color:var(--acc);font-size:.78rem}
.mcpc-sel-head{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.mcpc-search{flex:1;min-width:160px}
.mcpc-count{font-size:.75rem;color:var(--mut);font-family:var(--font-mono)}
.mcpc-list{max-height:460px;overflow-y:auto;border:1px solid var(--line);border-radius:6px;background:var(--card2)}
.mcpc-grp{border-bottom:1px solid var(--line)}
.mcpc-grp:last-child{border-bottom:none}
.mcpc-grp-h{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 11px;background:color-mix(in srgb,var(--bg) 40%,var(--card));position:sticky;top:0;z-index:1}
.mcpc-grp-name{font-size:.75rem;color:var(--mut);font-weight:600}
.mcpc-grp-sel{font-size:.75rem;color:var(--acc);cursor:pointer;background:none;border:none;font-family:inherit;padding:2px 4px}
.mcpc-grp-sel:hover{text-decoration:underline}
.mcpc-row{display:flex;align-items:center;gap:9px;padding:5px 11px;cursor:pointer;font-size:.8rem;color:var(--txt)}
.mcpc-row:hover{background:color-mix(in srgb,var(--acc) 8%,transparent)}
.mcpc-row input{width:14px;height:14px;flex:none;accent-color:var(--acc)}
.mcpc-row .mcpc-sec{font-family:var(--font-mono);font-size:.75rem;color:var(--mut);margin-left:auto}
.mcpc-row.hidden{display:none}
.mcpc-codebox{position:relative;margin:8px 0 0}
.mcpc-pre{font-family:var(--font-mono);font-size:.75rem;line-height:1.5;color:var(--txt);background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:12px 13px;margin:0;white-space:pre;overflow:auto;max-height:340px}
.mcpc-codebtns{display:flex;gap:7px;margin-top:8px;flex-wrap:wrap}
.mcpc-block-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 0 2px}
.mcpc-block-t{font-size:.875rem;font-weight:600;color:var(--txt);margin:0}
.mcpc-block-d{font-size:.76rem;color:var(--mut);margin:2px 0 0;line-height:1.5}
.mcpc-apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.mcpc-app{background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:11px 13px}
.mcpc-app h4{margin:0 0 4px;font-size:.8rem;color:var(--txt)}
.mcpc-app p{margin:0;font-size:.75rem;color:var(--mut);line-height:1.5}
.mcpc-sec-gap{margin-top:16px}
</style>`;

export function renderMcpConnector(main) {
  const origin = originOf();
  const tools = flattenTools();

  // Group for the selectable list, preserving NAV order.
  const groupOrder = [];
  const byGroup = new Map();
  for (const t of tools) {
    if (!byGroup.has(t.group)) { byGroup.set(t.group, []); groupOrder.push(t.group); }
    byGroup.get(t.group).push(t);
  }

  // Default selection: a small, representative starter set so the generated
  // config is useful immediately without overwhelming the client.
  const DEFAULT = new Set(
    ["citadel", "cvesearch", "regexlab", "encoding", "hashsuite", "dossier"]
      .filter((s) => tools.some((t) => t.sec === s))
  );
  if (!DEFAULT.size && tools.length) tools.slice(0, 6).forEach((t) => DEFAULT.add(t.sec));
  const selected = new Set(DEFAULT);

  const listHtml = groupOrder.map((gName) => {
    const rows = byGroup.get(gName).map((t) =>
      '<label class="mcpc-row" data-sec="' + esc(t.sec) + '" data-label="' + esc(t.label.toLowerCase()) + '">' +
        '<input type="checkbox" data-cb="' + esc(t.sec) + '"' + (selected.has(t.sec) ? " checked" : "") + '>' +
        '<span>' + esc(t.label) + '</span>' +
        '<span class="mcpc-sec">' + esc(t.sec) + '</span>' +
      '</label>'
    ).join("");
    return '<div class="mcpc-grp" data-grp="' + esc(gName) + '">' +
      '<div class="mcpc-grp-h">' +
        '<span class="mcpc-grp-name">' + esc(gName) + '</span>' +
        '<button type="button" class="mcpc-grp-sel" data-grpsel="' + esc(gName) + '">Select all</button>' +
      '</div>' + rows + '</div>';
  }).join("");

  function codeBlock(id, title, desc, dlName) {
    return '<div class="mcpc-sec-gap">' +
      '<div class="mcpc-block-h"><h3 class="mcpc-block-t">' + esc(title) + '</h3></div>' +
      '<p class="mcpc-block-d">' + esc(desc) + '</p>' +
      '<div class="mcpc-codebox"><pre class="mcpc-pre" id="' + id + '"></pre></div>' +
      '<div class="mcpc-codebtns">' +
        '<button class="btn sm" data-copy="' + id + '">Copy</button>' +
        '<button class="btn sm ghost" data-dl="' + id + '" data-dlname="' + esc(dlName) + '">Download</button>' +
      '</div></div>';
  }

  main.innerHTML = MCPC_CSS +
    '<div class="mcpc-wrap">' +
    '<div class="pg-head"><div>' +
      '<h1 class="pg-h1">MCP Connector</h1>' +
      '<p class="muted pg-sub">Connect AI clients to Darknode through the local <code>darknode mcp</code> server, and build a catalog of tool links. Everything here is generated in your browser.</p>' +
    '</div></div>' +

    '<div class="panel mcpc-sec-gap"><div class="panel-h"><h2 class="pg-h2">Two integration paths</h2></div>' +
      '<div class="mcpc-note">' +
        '<p><strong>1. MCP server.</strong> <code>darknode mcp</code> from darknode-cli runs on your computer and gives an MCP client (Claude Desktop, Claude Code and compatible agents) the Deck analysis tools your plan includes. The config below launches it; it does not depend on the tool selection on this page.</p>' +
        '<p><strong>2. Tool links.</strong> Every tool opens at its own route, for example <code>' + esc(origin) + '/citadel</code>. Adding <code>?embed=1</code> hides the Deck chrome. Embeds can only be framed by Darknode-origin pages, so other sites should link to tools rather than iframe them.</p>' +
      '</div>' +
    '</div>' +

    '<div class="mcpc-grid mcpc-sec-gap">' +
      '<div class="panel"><div class="panel-h"><h2 class="pg-h2">Tools for the link catalog</h2></div>' +
        '<div class="mcpc-sel-head" style="margin-bottom:10px">' +
          '<input class="mcpc-search" id="mcpc-search" placeholder="Filter tools">' +
          '<button class="btn sm ghost" id="mcpc-all">All</button>' +
          '<button class="btn sm ghost" id="mcpc-none">None</button>' +
        '</div>' +
        '<div class="mcpc-count" id="mcpc-count"></div>' +
        '<div class="mcpc-list" id="mcpc-list">' + listHtml + '</div>' +
      '</div>' +

      '<div class="panel"><div class="panel-h"><h2 class="pg-h2">Generated configuration</h2></div>' +
        codeBlock("mcpc-mcp", "MCP server config (Claude Desktop)",
          "Add under mcpServers after git clone https://github.com/Darknode-Official/darknode-cli and replace the path. Launches the Darknode MCP server on your computer with the Deck's analysis tools your plan includes. Setup for each AI client and keys for sending findings back: Deck > API & Ingest.",
          "darknode-mcp-config.json") +
        codeBlock("mcpc-cat", "Tool link catalog",
          "The selected tools with name, sec id and URL, for runbooks, wikis or your own integration. Links open the tool in Darknode; they are not an API.",
          "darknode-catalog.json") +
      '</div>' +
    '</div>' +

    '<div class="panel mcpc-sec-gap"><div class="panel-h"><h2 class="pg-h2">What each path is for</h2></div>' +
      '<div class="mcpc-apps">' +
        appCard("Claude Desktop and MCP clients", "Add the MCP config and the client can call the Darknode analysis tools your plan includes, running locally through darknode-cli.") +
        appCard("Internal wikis and runbooks", "Paste links from the catalog so responders open the right Darknode tool in one click.") +
        appCard("Darknode-origin pages", "Pages served from Darknode can iframe a tool at /<sec>?embed=1 to show it without the Deck chrome.") +
      '</div>' +
    '</div>' +

    '</div>';

  function appCard(title, body) {
    return '<div class="mcpc-app"><h4>' + esc(title) + '</h4><p>' + esc(body) + '</p></div>';
  }

  // ── Build generated payloads from the current selection ──
  function selectedTools() {
    return tools.filter((t) => selected.has(t.sec));
  }

  // The real server: `darknode mcp` from darknode-cli (git clone; npm is unavailable). It
  // serves the Deck's analysis tools the signed-in plan includes, not the embed list below.
  function mcpConfig() {
    return {
      mcpServers: {
        darknode: {
          command: "node",
          args: ["/full/path/to/darknode-cli/darknode.js", "mcp"]
        }
      }
    };
  }

  function catalog() {
    return {
      tools: selectedTools().map((t) => ({
        name: t.label,
        sec: t.sec,
        url: origin + "/" + t.sec,
        description: describe(t)
      }))
    };
  }

  // Store last-rendered text per box so copy/download read exactly what is shown.
  const texts = {};
  function setBox(id, text) {
    texts[id] = text;
    const el = main.querySelector("#" + id);
    if (el) el.textContent = text;
  }

  function regenerate() {
    const n = selected.size;
    setBox("mcpc-mcp", JSON.stringify(mcpConfig(), null, 2));
    setBox("mcpc-cat", JSON.stringify(catalog(), null, 2));
    const cnt = main.querySelector("#mcpc-count");
    if (cnt) cnt.textContent = n + " of " + tools.length + " tools selected";
    main.querySelectorAll("[data-cb]").forEach((cb) => { cb.checked = selected.has(cb.getAttribute("data-cb")); });
  }

  // ── Events ──
  const listEl = main.querySelector("#mcpc-list");
  listEl.addEventListener("change", (e) => {
    const cb = e.target.closest("input[data-cb]");
    if (!cb) return;
    const sec = cb.getAttribute("data-cb");
    if (cb.checked) selected.add(sec); else selected.delete(sec);
    regenerate();
  });
  listEl.addEventListener("click", (e) => {
    const btn = e.target.closest("[data-grpsel]");
    if (!btn) return;
    e.preventDefault();
    const gName = btn.getAttribute("data-grpsel");
    const secs = (byGroup.get(gName) || []).map((t) => t.sec);
    const allOn = secs.every((s) => selected.has(s));
    secs.forEach((s) => { if (allOn) selected.delete(s); else selected.add(s); });
    btn.textContent = allOn ? "Select all" : "Clear group";
    regenerate();
  });

  const searchEl = main.querySelector("#mcpc-search");
  searchEl.addEventListener("input", () => {
    const q = searchEl.value.trim().toLowerCase();
    main.querySelectorAll(".mcpc-row").forEach((r) => {
      const hay = (r.getAttribute("data-label") || "") + " " + (r.getAttribute("data-sec") || "");
      r.classList.toggle("hidden", !!q && hay.indexOf(q) === -1);
    });
    main.querySelectorAll(".mcpc-grp").forEach((g) => {
      const anyVisible = g.querySelector(".mcpc-row:not(.hidden)");
      g.style.display = anyVisible ? "" : "none";
    });
  });

  main.querySelector("#mcpc-all").addEventListener("click", () => {
    tools.forEach((t) => selected.add(t.sec));
    regenerate();
  });
  main.querySelector("#mcpc-none").addEventListener("click", () => {
    selected.clear();
    regenerate();
  });

  main.addEventListener("click", (e) => {
    const copyBtn = e.target.closest("[data-copy]");
    if (copyBtn) {
      const id = copyBtn.getAttribute("data-copy");
      copyText(texts[id] || "", "Copied " + id.replace("mcpc-", "") + " config");
      return;
    }
    const dlBtn = e.target.closest("[data-dl]");
    if (dlBtn) {
      const id = dlBtn.getAttribute("data-dl");
      downloadText(dlBtn.getAttribute("data-dlname") || "darknode.json", texts[id] || "");
    }
  });

  regenerate();
}
