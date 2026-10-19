// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Ingest: dropzone — browser-only file intake. Drag/drop (incl. folders),
// paste (text or files), Browse button and keyboard activation; archives are
// unpacked locally via ./unpack.js. Everything stays in the browser.
//
//   mountDropzone(el, opts) -> unmount()
//   onFiles(files, { skipped })  files: [{ name, size, type, bytes, text(), fromArchive? }]

import { unpackAll, canUnpack, magic, isArchiveName } from "./unpack.js";
import { decodeText } from "./parse.js";

const toast = (m, t) => { if (typeof window !== "undefined" && window.showToast) try { window.showToast(m, t || "info"); } catch (_) {} };
const fmt = (n) => (n >= (1 << 20) ? `${Math.round(n / (1 << 20))} MB` : `${Math.round(n / 1024)} KB`);

function injectStyle() {
  if (document.getElementById("dn-dropzone-css")) return;
  const st = document.createElement("style"); st.id = "dn-dropzone-css";
  st.textContent = `
  .dn-dz{position:relative;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;min-height:120px;padding:18px 14px;box-sizing:border-box;width:100%;max-width:100%;text-align:center;border:1.5px dashed var(--line,var(--border,#cdd3de));border-radius:10px;background:var(--card,var(--surface,#fff));color:var(--txt,#1a2230);cursor:pointer;outline:none;transition:border-color .12s,background .12s;overflow:hidden}
  .dn-dz:focus-visible{border-color:var(--acc,#2563eb);box-shadow:0 0 0 3px var(--acc-soft,rgba(37,99,235,.12))}
  .dn-dz.over{border-color:var(--acc,#2563eb);background:var(--acc-soft,rgba(37,99,235,.05))}
  .dn-dz.dn-dz-busy{opacity:.7;pointer-events:none}
  .dn-dz-label{font-size:.92rem;font-weight:600;line-height:1.4;overflow-wrap:anywhere;max-width:100%}
  .dn-dz-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:center;gap:8px;max-width:100%}
  .dn-dz-btn{appearance:none;font:inherit;font-size:.82rem;font-weight:600;border:1px solid var(--line,var(--border,#d7dbe3));background:var(--card,#fff);color:var(--txt,#1a2230);padding:6px 12px;border-radius:4px;cursor:pointer}
  .dn-dz-btn:hover{border-color:var(--acc,#2563eb)}
  .dn-dz-hint{font-size:.76rem;color:var(--mut,var(--muted,#667085));line-height:1.4;overflow-wrap:anywhere;max-width:100%}
  .dn-dz-note{font-size:.72rem;color:var(--mut,var(--muted,#667085));overflow-wrap:anywhere;max-width:100%}
  .dn-dz-input{position:absolute;width:1px;height:1px;opacity:0;pointer-events:none}`;
  document.head.appendChild(st);
}

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

/** Mount an accessible dropzone on `el`; returns an unmount function. */
export function mountDropzone(el, {
  accept = "", maxBytes = 8 << 20, maxFiles = 25, unpack = true, paste = true, multiple = true,
  onFiles, onError, label = "Drop files here, paste, or browse",
} = {}) {
  injectStyle();
  el.classList.add("dn-dz");
  el.setAttribute("tabindex", "0"); el.setAttribute("role", "button");
  el.setAttribute("aria-label", label);
  el.innerHTML = `<div class="dn-dz-label">${esc(label)}</div>
    <div class="dn-dz-row"><button type="button" class="dn-dz-btn">Browse</button>
      <span class="dn-dz-hint">Up to ${maxFiles} files, ${fmt(maxBytes)} each${unpack ? ", .zip/.gz unpacked" : ""}</span></div>
    <div class="dn-dz-note">Processed in your browser. Nothing is uploaded.</div>
    <input type="file" class="dn-dz-input" tabindex="-1" aria-hidden="true"${multiple ? " multiple" : ""}${accept ? ` accept="${esc(accept)}"` : ""}>`;
  const input = el.querySelector(".dn-dz-input"), browse = el.querySelector(".dn-dz-btn");
  const fail = (err) => { if (onError) onError(err); else toast(String(err && err.message || err), "error"); };

  async function toEntries(items, skipped) {
    const out = [];
    let archiveWarned = false;
    for (const it of items) {
      if (out.length >= maxFiles) { skipped.push({ name: it.name, reason: `over ${maxFiles} files` }); continue; }
      if (it.size > maxBytes) { skipped.push({ name: it.name, reason: `over ${fmt(maxBytes)}` }); continue; }
      let bytes;
      try { bytes = new Uint8Array(await it.arrayBuffer()); } catch (_) { skipped.push({ name: it.name, reason: "could not read" }); continue; }
      const kind = magic(bytes);
      // Magic bytes are authoritative; a .zip/.gz name without matching magic is not an archive we can open.
      if (unpack && !kind && isArchiveName(it.name)) { skipped.push({ name: it.name, reason: "not a zip or gzip archive (bad magic)" }); continue; }
      if (unpack && kind) {
        if (!canUnpack().deflateRaw && !archiveWarned) { archiveWarned = true; toast("This browser cannot unzip deflated archives; extract the archive and drop the files", "warning"); }
        try {
          const r = await unpackAll(bytes, { name: it.name, maxEntries: maxFiles - out.length, maxEntryBytes: maxBytes });
          for (const e of r.entries) out.push({ name: e.name, size: e.size, type: "", bytes: e.bytes, text: () => decodeText(e.bytes), fromArchive: e.fromArchive });
          for (const s of r.skipped) skipped.push({ name: `${it.name}/${s.name}`, reason: s.reason });
        } catch (err) { skipped.push({ name: it.name, reason: String(err && err.message || err) }); }
        continue;
      }
      out.push({ name: it.name, size: bytes.length, type: it.type || "", bytes, text: () => decodeText(bytes) });
    }
    return out;
  }

  async function deliver(items) {
    if (!items.length) return;
    el.classList.add("dn-dz-busy");
    try {
      const skipped = [];
      const files = await toEntries(items, skipped);
      if (onFiles) await onFiles(files, { skipped });
      if (skipped.length) toast(`${skipped.length} item${skipped.length > 1 ? "s" : ""} skipped: ${skipped[0].name} (${skipped[0].reason})`, "warning");
    } catch (err) { fail(err); } finally { el.classList.remove("dn-dz-busy"); }
  }

  // Folder drops: walk FileSystemEntry trees (webkitGetAsEntry), honoring caps.
  function walkEntry(ent, acc) {
    return new Promise((resolve) => {
      if (acc.length >= maxFiles) return resolve();
      if (ent.isFile) ent.file((f) => { acc.push(f); resolve(); }, () => resolve());
      else if (ent.isDirectory) {
        const reader = ent.createReader(), all = [];
        const more = () => reader.readEntries(async (batch) => {
          if (!batch.length) { for (const c of all) { if (acc.length >= maxFiles) break; await walkEntry(c, acc); } return resolve(); }
          all.push(...batch); more();
        }, () => resolve());
        more();
      } else resolve();
    });
  }
  async function fromDataTransfer(dt) {
    const items = dt.items ? Array.from(dt.items) : [];
    const entries = items.map((i) => (i.kind === "file" && i.webkitGetAsEntry ? i.webkitGetAsEntry() : null));
    if (entries.some((e) => e && e.isDirectory)) {
      const acc = [];
      for (const e of entries) { if (!e) continue; if (acc.length >= maxFiles) break; await walkEntry(e, acc); }
      return acc;
    }
    return Array.from(dt.files || []);
  }

  const onDragIn = (ev) => { ev.preventDefault(); el.classList.add("over"); };
  const onDragOut = (ev) => { ev.preventDefault(); if (ev.type === "dragleave" && el.contains(ev.relatedTarget)) return; el.classList.remove("over"); };
  const onDrop = async (ev) => { onDragOut(ev); if (!ev.dataTransfer) return; try { deliver(await fromDataTransfer(ev.dataTransfer)); } catch (err) { fail(err); } };
  const onPaste = (ev) => {
    const cd = ev.clipboardData; if (!cd) return;
    const files = Array.from(cd.files || []);
    if (files.length) { ev.preventDefault(); return deliver(files); }
    const text = cd.getData("text/plain");
    if (text) { ev.preventDefault(); deliver([new File([text], "pasted.txt", { type: "text/plain" })]); }
  };
  const onKey = (ev) => { if (ev.target !== el) return; if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); input.click(); } };
  const onBrowse = (ev) => { ev.stopPropagation(); input.click(); };
  const onClick = (ev) => { if (ev.target === el || ev.target.classList.contains("dn-dz-label")) input.click(); };
  const onChange = () => { deliver(Array.from(input.files || [])); input.value = ""; };

  el.addEventListener("dragenter", onDragIn); el.addEventListener("dragover", onDragIn);
  el.addEventListener("dragleave", onDragOut); el.addEventListener("drop", onDrop);
  el.addEventListener("keydown", onKey); el.addEventListener("click", onClick);
  browse.addEventListener("click", onBrowse); input.addEventListener("change", onChange);
  if (paste) el.addEventListener("paste", onPaste);

  return function unmount() {
    el.removeEventListener("dragenter", onDragIn); el.removeEventListener("dragover", onDragIn);
    el.removeEventListener("dragleave", onDragOut); el.removeEventListener("drop", onDrop);
    el.removeEventListener("keydown", onKey); el.removeEventListener("click", onClick);
    el.removeEventListener("paste", onPaste);
    el.classList.remove("dn-dz", "over", "dn-dz-busy");
    el.removeAttribute("role"); el.removeAttribute("tabindex"); el.removeAttribute("aria-label");
    el.innerHTML = "";
  };
}
