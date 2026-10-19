// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Ingest: worker runner — run an exported engine function off the main thread
// in a Blob module Worker, with progress, timeout, cancel and a main-thread
// fallback. No module-scope access to window/document/localStorage/fetch.
//
//   engineUrl(relPath, import.meta)                 -> absolute URL string
//   runInWorker(url, fnName, args, opts)            -> Promise<result> (+ .cancel())
//
// Engine convention: an engine module exports plain async/sync functions that
// take their arguments followed by a trailing OPTIONAL `ctx = { progress }`.
// `ctx.progress(done, total, label)` may be called freely; engines must also
// work when `ctx` is absent (callers importing the engine directly).
//
// Transfer: with `transfer: "auto"` every top-level ArrayBuffer / TypedArray
// buffer in `args` is moved (not copied) into the worker. The caller's copies
// are detached — the same as if the caller had posted them itself. Pass
// `transfer: false` to structured-clone instead, or an explicit array.

/** Resolve an engine path relative to the calling module. */
export function engineUrl(relPath, meta) { return new URL(relPath, meta.url).href; }

const workerSource = (url) => `import * as E from ${JSON.stringify(url)};
self.onmessage = async (e) => {
  try {
    const ctx = { progress: (done, total, label) => self.postMessage({ progress: { done, total, label } }) };
    const fn = E[e.data.fn];
    if (typeof fn !== "function") throw new Error("engine has no export " + JSON.stringify(e.data.fn));
    const out = await fn(...e.data.args, ctx);
    self.postMessage({ ok: true, out });
  } catch (err) { self.postMessage({ ok: false, error: String(err && err.message || err) }); }
};`;

// Copy an arg that would be detached by a transfer, so a fallback can still read it.
// ArrayBuffers and TypedArray/DataView views are copied; anything else passes through.
function cloneForInline(a) {
  if (a instanceof ArrayBuffer) return a.slice(0);
  if (a && ArrayBuffer.isView(a) && a.buffer instanceof ArrayBuffer) {
    if (typeof DataView !== "undefined" && a instanceof DataView) return new DataView(a.buffer.slice(a.byteOffset, a.byteOffset + a.byteLength));
    return new a.constructor(a);   // TypedArray ctor copies element-wise from the source view
  }
  return a;
}

function autoTransfer(args) {
  const list = [];
  for (const a of args) {
    if (a instanceof ArrayBuffer) list.push(a);
    else if (a && ArrayBuffer.isView(a) && a.buffer instanceof ArrayBuffer && !list.includes(a.buffer)) list.push(a.buffer);
  }
  return list;
}

async function runInline(url, fnName, args, onProgress) {
  const E = await import(url);
  const fn = E[fnName];
  if (typeof fn !== "function") throw new Error(`engine has no export ${JSON.stringify(fnName)}`);
  return fn(...args, { progress: onProgress || (() => {}) });
}

/**
 * Run `fnName(...args, ctx)` from the module at `url` in a Worker.
 * Falls back to the main thread when Workers/Blob URLs are unavailable or
 * the worker errors before producing any message.
 */
export function runInWorker(url, fnName, args = [], { onProgress, timeoutMs = 120000, transfer = "auto" } = {}) {
  const canWorker = typeof Worker !== "undefined" && typeof Blob !== "undefined" &&
    typeof URL !== "undefined" && typeof URL.createObjectURL === "function";
  let cancel = () => {};
  const p = new Promise((resolve, reject) => {
    if (!canWorker) { runInline(url, fnName, args, onProgress).then(resolve, reject); return; }
    let w = null, blobUrl = "", settled = false, spoke = false, timer = 0, inlineArgs = args;
    const cleanup = () => {
      if (timer) clearTimeout(timer);
      try { if (blobUrl) URL.revokeObjectURL(blobUrl); } catch (_) {}
      try { if (w) w.terminate(); } catch (_) {}
      w = null;
    };
    const finish = (ok, v) => { if (settled) return; settled = true; cleanup(); (ok ? resolve : reject)(v); };
    cancel = () => finish(false, new Error("cancelled"));
    try {
      blobUrl = URL.createObjectURL(new Blob([workerSource(url)], { type: "text/javascript" }));
      w = new Worker(blobUrl, { type: "module" });
      w.onmessage = (e) => {
        spoke = true;
        const d = e.data || {};
        if (d.progress) { if (onProgress) try { onProgress(d.progress.done, d.progress.total, d.progress.label); } catch (_) {} return; }
        if (d.ok) finish(true, d.out); else finish(false, new Error(d.error || "worker error"));
      };
      w.onerror = (ev) => {
        if (settled) return;
        if (!spoke) { settled = true; cleanup(); runInline(url, fnName, inlineArgs, onProgress).then(resolve, reject); return; }
        finish(false, new Error(String(ev && ev.message || "worker error")));
      };
      const list = transfer === "auto" ? autoTransfer(args) : Array.isArray(transfer) ? transfer : [];
      // Posting transfers (detaches) every buffer in `list`, so the main-thread fallback can't
      // re-read `args` — keep a non-detached copy for it. Only costs a copy when transferring.
      if (list.length) inlineArgs = args.map(cloneForInline);
      w.postMessage({ fn: fnName, args }, list);
      if (timeoutMs > 0) timer = setTimeout(() => finish(false, new Error("worker timeout")), timeoutMs);
    } catch (_) {
      if (settled) return;
      settled = true; cleanup();
      runInline(url, fnName, inlineArgs, onProgress).then(resolve, reject);
    }
  });
  p.cancel = () => cancel();
  return p;
}
