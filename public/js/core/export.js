// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Shared export helpers: CSV / JSON / NDJSON / ICS text, a hand-rolled zip writer
// and the browser download shim. Everything but download() is pure and node-safe.

export { toCSV as toCsv } from "./findings.js";

/**
 * Trigger a browser file download. Throws outside a browser.
 * @param {string} name file name
 * @param {string|Uint8Array|Blob} text contents
 * @param {string} [type="text/plain"] MIME type
 */
export function download(name, text, type = "text/plain") {
  if (typeof document === "undefined") throw new Error("download() requires a browser");
  const b = text instanceof Blob ? text : new Blob([text], { type });
  const u = URL.createObjectURL(b); const a = document.createElement("a");
  a.href = u; a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(u), 1000);
}

/** Pretty JSON (2-space). */
export function toJson(v) { return JSON.stringify(v, null, 2) + "\n"; }

/** Newline-delimited JSON, one row per line. */
export function toNdjson(rows) { return (rows || []).map((r) => JSON.stringify(r)).join("\n") + "\n"; }

/**
 * Local-time file stamp, YYYYMMDD-HHMM.
 * @param {Date} [d=new Date()]
 */
export function fileStamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}`;
}

// ---------------------------------------------------------------------------
// ICS (RFC 5545)
// ---------------------------------------------------------------------------

const icsEsc = (s) => String(s == null ? "" : s).replace(/\\/g, "\\\\").replace(/;/g, "\\;").replace(/,/g, "\\,").replace(/\r\n|\r|\n/g, "\\n");
const icsUtc = (d) => new Date(d).toISOString().replace(/[-:]/g, "").replace(/\.\d{3}Z$/, "Z");
const icsDate = (d) => { const x = new Date(d); return x.toISOString().slice(0, 10).replace(/-/g, ""); };

/** Fold a content line at 75 octets (UTF-8), continuation lines start with a space. */
export function icsFold(line) {
  const enc = new TextEncoder(), dec = new TextDecoder();
  const bytes = enc.encode(line);
  if (bytes.length <= 75) return line;
  const out = [];
  let i = 0, limit = 75;
  while (i < bytes.length) {
    let end = Math.min(i + limit, bytes.length);
    while (end < bytes.length && end > i && (bytes[end] & 0xc0) === 0x80) end--; // don't split a code point
    out.push((i ? " " : "") + dec.decode(bytes.subarray(i, end)));
    i = end; limit = 74;
  }
  return out.join("\r\n");
}

/**
 * Minimal VCALENDAR. events: [{ uid?, start, end?, allDay?, summary, description?, stamp? }].
 * @param {object[]} events
 * @param {{ prodId?: string }} [o]
 * @returns {string}
 */
export function toIcs(events, { prodId = "-//Darknode//Deck//EN" } = {}) {
  const lines = ["BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:" + prodId, "CALSCALE:GREGORIAN"];
  (events || []).forEach((e, i) => {
    const uid = e.uid || `${icsUtc(e.stamp || e.start || Date.now())}-${i}@darknode.ai`;
    lines.push("BEGIN:VEVENT", "UID:" + icsEsc(uid), "DTSTAMP:" + icsUtc(e.stamp || Date.now()));
    if (e.allDay) {
      lines.push("DTSTART;VALUE=DATE:" + icsDate(e.start));
      if (e.end) lines.push("DTEND;VALUE=DATE:" + icsDate(e.end));
    } else {
      lines.push("DTSTART:" + icsUtc(e.start));
      if (e.end) lines.push("DTEND:" + icsUtc(e.end));
    }
    lines.push("SUMMARY:" + icsEsc(e.summary));
    if (e.description) lines.push("DESCRIPTION:" + icsEsc(e.description));
    lines.push("END:VEVENT");
  });
  lines.push("END:VCALENDAR");
  return lines.map(icsFold).join("\r\n") + "\r\n";
}

// ---------------------------------------------------------------------------
// ZIP writer (APPNOTE 4.4.x): local headers + central directory + EOCD.
// Method 0 (store) always works; method 8 (deflate) via CompressionStream
// ("deflate-raw") when the runtime has it and `compress` is set.
// ---------------------------------------------------------------------------

const CRC_TABLE = (() => {
  const t = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    t[n] = c >>> 0;
  }
  return t;
})();

/** CRC-32 (IEEE) of a byte array. */
export function crc32(bytes) {
  let c = 0xffffffff;
  for (let i = 0; i < bytes.length; i++) c = CRC_TABLE[(c ^ bytes[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

function dosDateTime(d) {
  const time = (d.getHours() << 11) | (d.getMinutes() << 5) | (d.getSeconds() >> 1);
  const date = ((d.getFullYear() - 1980) << 9) | ((d.getMonth() + 1) << 5) | d.getDate();
  return { time: time & 0xffff, date: date & 0xffff };
}

async function deflateRaw(bytes) {
  let cs;
  try { cs = new CompressionStream("deflate-raw"); } catch (_) { return null; }
  const stream = new Blob([bytes]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/**
 * Build a zip archive in memory.
 * @param {{ name: string, text?: string, bytes?: Uint8Array, date?: Date }[]} files
 * @param {{ compress?: boolean }} [o]
 * @returns {Promise<Uint8Array>}
 */
export async function zipFiles(files, { compress = true } = {}) {
  const enc = new TextEncoder();
  const canDeflate = compress && typeof CompressionStream === "function" && typeof Blob === "function" && typeof Response === "function";
  const parts = [], central = [];
  let offset = 0;
  const u16 = (v) => [v & 0xff, (v >>> 8) & 0xff];
  const u32 = (v) => [v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff];
  const push = (arr) => { const b = arr instanceof Uint8Array ? arr : Uint8Array.from(arr); parts.push(b); offset += b.length; };
  for (const f of files || []) {
    const nameB = enc.encode(String(f.name || "file"));
    const raw = f.bytes instanceof Uint8Array ? f.bytes : enc.encode(String(f.text == null ? "" : f.text));
    const crc = crc32(raw);
    let method = 0, body = raw;
    if (canDeflate && raw.length) {
      const z = await deflateRaw(raw);
      if (z && z.length < raw.length) { method = 8; body = z; }
    }
    const { time, date } = dosDateTime(f.date instanceof Date ? f.date : new Date());
    const local = offset;
    push([...u32(0x04034b50), ...u16(20), ...u16(0x0800), ...u16(method), ...u16(time), ...u16(date),
      ...u32(crc), ...u32(body.length), ...u32(raw.length), ...u16(nameB.length), ...u16(0)]);
    push(nameB); push(body);
    central.push(Uint8Array.from([...u32(0x02014b50), ...u16(20), ...u16(20), ...u16(0x0800), ...u16(method), ...u16(time), ...u16(date),
      ...u32(crc), ...u32(body.length), ...u32(raw.length), ...u16(nameB.length), ...u16(0), ...u16(0), ...u16(0), ...u16(0),
      ...u32(0), ...u32(local), ...nameB]));
  }
  const cdStart = offset;
  for (const c of central) push(c);
  const cdSize = offset - cdStart;
  push([...u32(0x06054b50), ...u16(0), ...u16(0), ...u16(central.length), ...u16(central.length), ...u32(cdSize), ...u32(cdStart), ...u16(0)]);
  const out = new Uint8Array(offset);
  let p = 0;
  for (const b of parts) { out.set(b, p); p += b.length; }
  return out;
}
