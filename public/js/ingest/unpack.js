// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
//
// Ingest: unpack — hand-rolled ZIP reader + gzip/deflate via the native
// DecompressionStream. Zero dependencies; no module-scope access to window,
// document, localStorage or fetch so it loads in Node 20 and inside a Blob
// module Worker alike.
//
//   unpack(bytes, opts)      async generator of entries (zip / gzip / plain)
//   unpackAll(bytes, opts)   -> { entries, skipped }
//   unzip(bytes, caps)       async generator over a .zip
//   gunzip(bytes)            -> Uint8Array
//   inflateRaw(bytes)        -> Uint8Array
//   canUnpack()              -> { zip, gzip, deflateRaw }
//   isArchiveName(name)      -> boolean
//   magic(bytes)             -> "zip" | "gzip" | null
//
// Entry shape: { name, size, bytes, text(), path: string[], fromArchive }.
// Refuses encrypted, zip64 and non-store/deflate members with a clear Error.
// Entries beyond the caps are not yielded; they are reported in the
// generator's return value `{ skipped: [{ name, reason }] }`.

const SIG_LOCAL = 0x04034b50, SIG_CENTRAL = 0x02014b50, SIG_EOCD = 0x06054b50, SIG_EOCD64 = 0x06064b50;
const EOCD_SCAN = 65557; // 22-byte EOCD + 65535-byte max comment

const dec8 = typeof TextDecoder !== "undefined" ? new TextDecoder("utf-8") : null;
const decLatin = typeof TextDecoder !== "undefined" ? new TextDecoder("latin1") : null;
/** Minimal utf-8 fallback so the module never depends on the host decoder. */
function utf8(u8) {
  if (dec8) return dec8.decode(u8);
  let s = "";
  for (let i = 0; i < u8.length;) {
    const b = u8[i++];
    if (b < 0x80) s += String.fromCharCode(b);
    else if (b < 0xe0) s += String.fromCharCode(((b & 0x1f) << 6) | (u8[i++] & 0x3f));
    else if (b < 0xf0) s += String.fromCharCode(((b & 0x0f) << 12) | ((u8[i++] & 0x3f) << 6) | (u8[i++] & 0x3f));
    else { const cp = ((b & 0x07) << 18) | ((u8[i++] & 0x3f) << 12) | ((u8[i++] & 0x3f) << 6) | (u8[i++] & 0x3f); s += String.fromCodePoint(cp); }
  }
  return s;
}
function latin1(u8) {
  if (decLatin) return decLatin.decode(u8);
  let s = ""; for (let i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]); return s;
}

const toU8 = (b) => (b instanceof Uint8Array ? b : b instanceof ArrayBuffer ? new Uint8Array(b) : new Uint8Array(b.buffer || b));

/** Detect archive type by leading bytes. */
export function magic(bytes) {
  const u = toU8(bytes);
  if (u.length >= 4 && u[0] === 0x50 && u[1] === 0x4b && u[2] === 0x03 && u[3] === 0x04) return "zip";
  if (u.length >= 2 && u[0] === 0x1f && u[1] === 0x8b) return "gzip";
  return null;
}

export function isArchiveName(name) { return /\.(zip|gz|gzip)$/i.test(String(name || "")); }

/** Which formats the host DecompressionStream supports. */
export function canUnpack() {
  const has = (f) => { try { new DecompressionStream(f); return true; } catch (_) { return false; } };
  const ok = typeof DecompressionStream !== "undefined";
  const deflateRaw = ok && has("deflate-raw"), gzip = ok && has("gzip");
  return { zip: true, gzip, deflateRaw };
}

async function decompress(bytes, format) {
  if (typeof DecompressionStream === "undefined") throw new Error(`DecompressionStream unavailable (${format})`);
  const u = toU8(bytes);
  const ds = new DecompressionStream(format);
  const stream = new Blob([u]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}
export function gunzip(bytes) { return decompress(bytes, "gzip"); }
export function inflateRaw(bytes) { return decompress(bytes, "deflate-raw"); }

/** Normalize a zip member name into a safe path (no abs, no .., fwd slashes). */
export function sanitizePath(name) {
  const parts = String(name || "").replace(/\\/g, "/").split("/").filter((p) => p && p !== "." && p !== "..");
  return parts;
}

function entry(name, bytes, fromArchive) {
  const path = sanitizePath(name);
  return { name: path.join("/") || name, size: bytes.length, bytes, text: () => utf8(bytes), path, fromArchive };
}

function caps(o = {}) {
  return {
    maxEntries: o.maxEntries ?? 500, maxEntryBytes: o.maxEntryBytes ?? (64 << 20),
    maxTotalBytes: o.maxTotalBytes ?? (256 << 20), maxRatio: o.maxRatio ?? 200,
  };
}

/** Read a .zip; yields entries, returns { skipped }. */
export async function* unzip(bytes, opts = {}) {
  const u = toU8(bytes), c = caps(opts), from = opts.name || "archive.zip";
  const dv = new DataView(u.buffer, u.byteOffset, u.byteLength);
  const u32 = (p) => dv.getUint32(p, true), u16 = (p) => dv.getUint16(p, true);
  if (u.length < 22) throw new Error("not a zip: too short");
  let eocd = -1;
  for (let p = u.length - 22, lo = Math.max(0, u.length - EOCD_SCAN); p >= lo; p--) { if (u32(p) === SIG_EOCD) { eocd = p; break; } }
  if (eocd < 0) throw new Error("not a zip: end-of-central-directory record missing");
  if (eocd >= 20 && u32(eocd - 20) === 0x07064b50) throw new Error("zip64 archives are not supported");
  const count = u16(eocd + 10), cdSize = u32(eocd + 12), cdOff = u32(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) throw new Error("zip64 archives are not supported");
  if (cdOff + cdSize > u.length) throw new Error("corrupt zip: central directory out of range");
  if (u32(cdOff) === SIG_EOCD64) throw new Error("zip64 archives are not supported");

  const skipped = [];
  let p = cdOff, yielded = 0, total = 0;
  for (let i = 0; i < count; i++) {
    if (p + 46 > u.length || u32(p) !== SIG_CENTRAL) throw new Error("corrupt zip: bad central directory entry");
    const flags = u16(p + 8), method = u16(p + 10), csize = u32(p + 20), usize = u32(p + 24);
    const nlen = u16(p + 28), xlen = u16(p + 30), clen = u16(p + 32), loff = u32(p + 42);
    const rawName = u.subarray(p + 46, p + 46 + nlen);
    const name = (flags & 0x800) ? utf8(rawName) : latin1(rawName);
    p += 46 + nlen + xlen + clen;

    if (name.endsWith("/")) continue; // directory
    if (flags & 1) throw new Error(`encrypted zip entry: ${name}`);
    if (csize === 0xffffffff || usize === 0xffffffff || loff === 0xffffffff) throw new Error("zip64 archives are not supported");
    if (method !== 0 && method !== 8) throw new Error(`unsupported compression method ${method} (${name})`);
    if (csize > 0 && usize / csize > c.maxRatio && usize > 10 * 1024 * 1024) throw new Error(`suspicious compression ratio in ${name} (possible zip bomb)`);
    if (yielded >= c.maxEntries) { skipped.push({ name, reason: `over ${c.maxEntries} entries` }); continue; }
    if (usize > c.maxEntryBytes) { skipped.push({ name, reason: `entry over ${fmtBytes(c.maxEntryBytes)}` }); continue; }
    if (total + usize > c.maxTotalBytes) { skipped.push({ name, reason: `total over ${fmtBytes(c.maxTotalBytes)}` }); continue; }

    if (loff + 30 > u.length || u32(loff) !== SIG_LOCAL) throw new Error(`corrupt zip: bad local header for ${name}`);
    const dataStart = loff + 30 + u16(loff + 26) + u16(loff + 28);
    if (dataStart + csize > u.length) throw new Error(`corrupt zip: data out of range for ${name}`);
    const raw = u.slice(dataStart, dataStart + csize);
    let out;
    if (method === 0) out = raw;
    else {
      out = await inflateRaw(raw);
      if (out.length > c.maxEntryBytes) { skipped.push({ name, reason: `entry over ${fmtBytes(c.maxEntryBytes)}` }); continue; }
    }
    yielded++; total += out.length;
    yield entry(name, out, from);
  }
  return { skipped };
}

function fmtBytes(n) { return n >= (1 << 20) ? `${Math.round(n / (1 << 20))} MB` : `${Math.round(n / 1024)} KB`; }

const stripGz = (n) => String(n || "").replace(/\.(gz|gzip)$/i, "") || "data";

/**
 * Unpack any input: zip -> members, gzip -> one entry, else the input itself.
 * Recurses one level into .gz / .zip members of a zip (depth limit 2).
 */
export async function* unpack(bytes, opts = {}) {
  const u = toU8(bytes), name = opts.name || "", depth = opts._depth || 0, c = caps(opts);
  const kind = magic(u);
  const skipped = [];
  if (kind === "gzip") {
    const out = await gunzip(u);
    if (out.length > c.maxEntryBytes) { skipped.push({ name: stripGz(name), reason: `entry over ${fmtBytes(c.maxEntryBytes)}` }); return { skipped }; }
    yield entry(stripGz(name), out, name || "data.gz");
    return { skipped };
  }
  if (kind === "zip") {
    const inner = unzip(u, { ...c, name: name || "archive.zip" });
    for (;;) {
      const r = await inner.next();
      if (r.done) { skipped.push(...(r.value && r.value.skipped || [])); break; }
      const e = r.value;
      const innerKind = depth < 1 && isArchiveName(e.name) ? magic(e.bytes) : null;
      if (innerKind) {
        const sub = unpack(e.bytes, { ...c, name: e.name, _depth: depth + 1 });
        for (;;) {
          const s = await sub.next();
          if (s.done) { skipped.push(...(s.value && s.value.skipped || [])); break; }
          const se = s.value;
          se.fromArchive = `${e.fromArchive}/${e.name}`;
          // gz members keep their own dir (name carried the full path); zip
          // members are relative to the inner zip, so nest under its folder.
          if (innerKind === "zip") { se.path = [...e.path.slice(0, -1), ...se.path]; se.name = se.path.join("/"); }
          yield se;
        }
      } else yield e;
    }
    return { skipped };
  }
  yield { name: name || "data", size: u.length, bytes: u, text: () => utf8(u), path: sanitizePath(name || "data"), fromArchive: "" };
  return { skipped };
}

/** Collect every entry plus the skipped report. */
export async function unpackAll(bytes, opts = {}) {
  const entries = [], gen = unpack(bytes, opts);
  for (;;) {
    const r = await gen.next();
    if (r.done) return { entries, skipped: (r.value && r.value.skipped) || [] };
    entries.push(r.value);
  }
}
