// MCP Connector — "Connect to Darknode" interop hub.
// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
//
// Lets other apps and AI agents use Darknode's tools two ways:
//   (a) embeddable UIs via `?embed=1` (same-origin iframes), and
//   (b) an MCP (Model Context Protocol) server config that points an AI client
//       (Claude Desktop, etc.) at Darknode's tool catalog.
// This module is a generator/documentation surface only — it makes NO network
// calls. Everything it produces is computed locally from the live tool catalog
// and shown in copyable code boxes.

import { NAV } from "/js/console-nav.js?v=20261013k";

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
  return t.label + " — Darknode tool (group: " + t.group + "), served as an embeddable read-only UI at /" + t.sec + "?embed=1.";
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
.mcpc-count{font-size:.74rem;color:var(--mut);font-family:var(--font-mono)}
.mcpc-list{max-height:460px;overflow-y:auto;border:1px solid var(--line);border-radius:6px;background:var(--card2)}
.mcpc-grp{border-bottom:1px solid var(--line)}
.mcpc-grp:last-child{border-bottom:none}
.mcpc-grp-h{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:7px 11px;background:color-mix(in srgb,var(--bg) 40%,var(--card));position:sticky;top:0;z-index:1}
.mcpc-grp-name{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut);font-weight:700}
.mcpc-grp-sel{font-size:.7rem;color:var(--acc);cursor:pointer;background:none;border:none;font-family:inherit;padding:2px 4px}
.mcpc-grp-sel:hover{text-decoration:underline}
.mcpc-row{display:flex;align-items:center;gap:9px;padding:5px 11px;cursor:pointer;font-size:.8rem;color:var(--txt)}
.mcpc-row:hover{background:color-mix(in srgb,var(--acc) 8%,transparent)}
.mcpc-row input{width:14px;height:14px;flex:none;accent-color:var(--acc)}
.mcpc-row .mcpc-sec{font-family:var(--font-mono);font-size:.7rem;color:var(--mut);margin-left:auto}
.mcpc-row.hidden{display:none}
.mcpc-codebox{position:relative;margin:8px 0 0}
.mcpc-pre{font-family:var(--font-mono);font-size:.74rem;line-height:1.5;color:var(--txt);background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:12px 13px;margin:0;white-space:pre;overflow:auto;max-height:340px}
.mcpc-codebtns{display:flex;gap:7px;margin-top:8px;flex-wrap:wrap}
.mcpc-block-h{display:flex;align-items:center;justify-content:space-between;gap:10px;margin:0 0 2px}
.mcpc-block-t{font-size:.84rem;font-weight:700;color:var(--txt);margin:0}
.mcpc-block-d{font-size:.76rem;color:var(--mut);margin:2px 0 0;line-height:1.5}
.mcpc-apps{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.mcpc-app{background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:11px 13px}
.mcpc-app h4{margin:0 0 4px;font-size:.8rem;color:var(--txt)}
.mcpc-app p{margin:0;font-size:.74rem;color:var(--mut);line-height:1.5}
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
    ["prometheus", "citadel", "cvesearch", "regexlab", "encoding", "hashsuite", "whoisrecon"]
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
      '<p class="muted pg-sub">Connect other apps and AI agents to Darknode tools via MCP, same-origin embeds, and a read-only API. Everything below is generated locally from the live catalog — no data leaves your browser.</p>' +
    '</div></div>' +

    '<div class="panel mcpc-sec-gap"><div class="panel-h"><h2 class="pg-h2">How Darknode exposes its tools</h2></div>' +
      '<div class="mcpc-note">' +
        '<p>Darknode makes its ' + tools.length + ' tools available to outside software in two ways:</p>' +
        '<p><strong>1. Embeddable UIs.</strong> Every tool renders inside a same-origin iframe with the shell stripped out by appending <code>?embed=1</code> to its route — for example <code>' + esc(origin) + '/citadel?embed=1</code>. Any app can drop these into an iframe to give users a Darknode tool in place.</p>' +
        '<p><strong>2. MCP server config.</strong> The Model Context Protocol lets an AI client (Claude Desktop and compatible agents) discover and open tools from a server. The config below points such a client at a <code>darknode</code> MCP server that advertises the tools you select as resources, each resolving to its embed URL.</p>' +
        '<p>Pick the tools you want to expose, then copy or download the generated configs. This page performs no backend calls — it is purely a generator and documentation surface.</p>' +
      '</div>' +
    '</div>' +

    '<div class="mcpc-grid mcpc-sec-gap">' +
      '<div class="panel"><div class="panel-h"><h2 class="pg-h2">Select tools to expose</h2></div>' +
        '<div class="mcpc-sel-head" style="margin-bottom:10px">' +
          '<input class="mcpc-search" id="mcpc-search" placeholder="Filter tools...">' +
          '<button class="btn sm ghost" id="mcpc-all">All</button>' +
          '<button class="btn sm ghost" id="mcpc-none">None</button>' +
        '</div>' +
        '<div class="mcpc-count" id="mcpc-count"></div>' +
        '<div class="mcpc-list" id="mcpc-list">' + listHtml + '</div>' +
      '</div>' +

      '<div class="panel"><div class="panel-h"><h2 class="pg-h2">Generated configuration</h2></div>' +
        codeBlock("mcpc-mcp", "MCP server config (Claude Desktop)",
          "Add to your MCP client config under mcpServers. Launches the darknode MCP server, which serves the selected tools as resources.",
          "darknode-mcp-config.json") +
        codeBlock("mcpc-cat", "Tool catalog (readable)",
          "The selected tools with name, sec id, embed url and description — consumed by the darknode MCP server or any custom integration.",
          "darknode-catalog.json") +
        codeBlock("mcpc-openapi", "Read-only API manifest (OpenAPI 3.1)",
          "Documents the embed surface as GET endpoints other apps can consume. Each path returns the tool's embeddable HTML UI.",
          "darknode-embed-api.json") +
        codeBlock("mcpc-curl", "Fetch example",
          "A cURL and a JavaScript fetch against one selected tool's embed URL.",
          "darknode-embed-example.txt") +
      '</div>' +
    '</div>' +

    '<div class="panel mcpc-sec-gap"><div class="panel-h"><h2 class="pg-h2">Connected apps — what each integration enables</h2></div>' +
      '<div class="mcpc-apps">' +
        appCard("Claude Desktop / MCP clients", "Drop the MCP server config in and the agent can list and open your selected Darknode tools as resources during a conversation, resolving each to its live embed UI.") +
        appCard("AI coding agents", "Point an agent at the tool catalog JSON so it knows which Darknode capabilities exist and the exact embed URL to open for each task.") +
        appCard("Web apps & portals", "Embed any tool with an iframe pointing at /<sec>?embed=1 — the shell, sidebar and auth chrome are removed, leaving just the tool UI.") +
        appCard("Dashboards & SIEMs", "Use the OpenAPI manifest to register Darknode tools as linkable read-only panels alongside your existing views.") +
        appCard("Internal wikis & runbooks", "Link directly to embed URLs from documentation so responders launch the right tool in one click, in context.") +
        appCard("Custom integrations", "The readable catalog and OpenAPI manifest are plain JSON — wire them into any orchestrator, bot, or automation you build.") +
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

  function mcpConfig() {
    return {
      mcpServers: {
        darknode: {
          command: "npx",
          args: ["-y", "@darknode/mcp"],
          env: {
            DARKNODE_ORIGIN: origin,
            DARKNODE_TOOLS: selectedTools().map((t) => t.sec).join(",")
          }
        }
      }
    };
  }

  function catalog() {
    return {
      tools: selectedTools().map((t) => ({
        name: t.label,
        sec: t.sec,
        url: origin + "/" + t.sec + "?embed=1",
        description: describe(t)
      }))
    };
  }

  function openapi() {
    const paths = {};
    for (const t of selectedTools()) {
      paths["/" + t.sec] = {
        get: {
          operationId: t.sec,
          summary: t.label,
          description: describe(t),
          tags: [t.group],
          parameters: [{
            name: "embed", in: "query", required: true,
            description: "Render the tool UI without the Darknode shell.",
            schema: { type: "integer", enum: [1] }
          }],
          responses: {
            "200": {
              description: "Embeddable HTML UI for " + t.label,
              content: { "text/html": { schema: { type: "string" } } }
            }
          }
        }
      };
    }
    return {
      openapi: "3.1.0",
      info: {
        title: "Darknode Embed API",
        version: "1.0.0",
        description: "Read-only surface exposing Darknode tools as same-origin embeddable UIs. Append ?embed=1 to any tool route."
      },
      servers: [{ url: origin }],
      paths
    };
  }

  function curlExample() {
    const t = selectedTools()[0] || tools[0];
    if (!t) return "Select at least one tool to generate an example.";
    const url = origin + "/" + t.sec + "?embed=1";
    return "# " + t.label + " — embeddable UI\n" +
      "curl -s '" + url + "'\n\n" +
      "// Or embed it in a page:\n" +
      "const res = await fetch('" + url + "');\n" +
      "const html = await res.text();\n" +
      "// document.querySelector('#frame').srcdoc = html;\n\n" +
      "// Or drop it straight into an iframe (same-origin):\n" +
      "// <iframe src=\"" + url + "\" title=\"" + t.label + "\"></iframe>";
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
    setBox("mcpc-openapi", JSON.stringify(openapi(), null, 2));
    setBox("mcpc-curl", curlExample());
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
