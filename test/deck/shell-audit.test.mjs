// Deck shell audit regressions: archive caps that bound real memory (gzip/deflate bombs,
// nested-zip amplification), CSV stray quotes and "__proto__" headers, and VAULT
// inherited-key lookups ("constructor" as an op or an account type).

import { gzipSync, deflateRawSync } from "node:zlib";
import { test, assert, group } from "../harness.mjs";
import { unpackAll, gunzip, inflateRaw, canUnpack } from "../../public/js/ingest/unpack.js";
import { parseCsv } from "../../public/js/ingest/parse.js";
import { canDo } from "../../public/js/vault/roles.js";
import { Ledger } from "../../public/js/vault/ledger.js";

const enc = new TextEncoder();

// Minimal zip writer, stored or deflate (`usize` given) (CRC left 0: the reader does not check it).
function zip(entries) {
  const parts = [], central = [];
  let off = 0;
  for (const { name, data, usize } of entries) {
    const method = usize == null ? 0 : 8, us = usize == null ? data.length : usize;
    const nb = enc.encode(name);
    const lh = new Uint8Array(30 + nb.length), lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(6, 0x800, true); lv.setUint16(8, method, true);
    lv.setUint32(18, data.length, true); lv.setUint32(22, us, true); lv.setUint16(26, nb.length, true);
    lh.set(nb, 30); parts.push(lh, data);
    const ch = new Uint8Array(46 + nb.length), cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(8, 0x800, true); cv.setUint16(10, method, true);
    cv.setUint32(20, data.length, true); cv.setUint32(24, us, true); cv.setUint16(28, nb.length, true);
    cv.setUint32(42, off, true); ch.set(nb, 46); central.push(ch);
    off += lh.length + data.length;
  }
  const cdSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22), ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true); ev.setUint32(16, off, true);
  const all = [...parts, ...central, eocd], out = new Uint8Array(all.reduce((n, p) => n + p.length, 0));
  let p = 0; for (const a of all) { out.set(a, p); p += a.length; }
  return out;
}

group("deck shell audit: archive caps", () => {
  const CAN = canUnpack();
  if (CAN.gzip) test("gunzip with a cap stops early and returns null instead of inflating the whole bomb", async () => {
    const bomb = gzipSync(new Uint8Array(8 << 20)); // ~8 KB on disk, 8 MB inflated
    assert.equal(await gunzip(bomb, 64 << 10), null);
    assert.equal((await gunzip(bomb)).length, 8 << 20); // uncapped callers unchanged
  });
  if (CAN.deflateRaw) test("inflateRaw with a cap ignores the archive's own size claims", async () => {
    assert.equal(await inflateRaw(deflateRawSync(new Uint8Array(4 << 20)), 1 << 20), null);
  });
  if (CAN.gzip) test("a gzip over the entry cap is skipped, not yielded", async () => {
    const r = await unpackAll(gzipSync(new Uint8Array(2 << 20)), { name: "big.log.gz", maxEntryBytes: 1 << 20 });
    assert.equal(r.entries.length, 0);
    assert.equal(r.skipped.length, 1);
  });
  test("entry cap is shared with nested zips (no per-archive reset)", async () => {
    const inner = (tag) => zip([1, 2, 3].map((i) => ({ name: `${tag}${i}.txt`, data: enc.encode("x") })));
    const outer = zip([{ name: "a.zip", data: inner("a") }, { name: "b.zip", data: inner("b") }]);
    const r = await unpackAll(outer, { name: "outer.zip", maxEntries: 4 });
    assert.equal(r.entries.length, 4);
    assert.equal(r.skipped.length, 2);
  });
  test("a nested archive's own slot is refunded: one slot left still yields its member", async () => {
    const outer = zip([{ name: "only.zip", data: zip([{ name: "f.txt", data: enc.encode("hi") }]) }]);
    const r = await unpackAll(outer, { name: "outer.zip", maxEntries: 1 });
    assert.deepEqual(r.entries.map((e) => e.name), ["f.txt"]);
  });
  if (CAN.deflateRaw) test("total byte cap is shared with nested zips (inflated bytes, not the inner archive's size)", async () => {
    const inner = (tag) => zip([{ name: tag + ".txt", data: deflateRawSync(new Uint8Array(600)), usize: 600 }]);
    const outer = zip([{ name: "a.zip", data: inner("a") }, { name: "b.zip", data: inner("b") }]);
    const r = await unpackAll(outer, { name: "outer.zip", maxTotalBytes: 1000 });
    assert.equal(r.entries.length, 1);
  });
});

group("deck shell audit: CSV parsing", () => {
  test("a quote inside an unquoted field is literal and does not swallow later rows", () => {
    const { rows } = parseCsv('host,note\nweb01,5" rack\nweb02,ok\nweb03,"quoted, field"\n');
    assert.equal(rows.length, 3);
    assert.equal(rows[0].note, '5" rack');
    assert.equal(rows[1].host, "web02");
    assert.equal(rows[2].note, "quoted, field");
  });
  test("a repeated __proto__ header is de-duplicated like any other name", () => {
    const { headers, rows } = parseCsv("__proto__,__proto__,x\n1,2,3\n");
    assert.deepEqual(headers, ["__proto__", "__proto___2", "x"]);
    assert.equal(rows[0].__proto___2, "2");
  });
});

group("deck shell audit: VAULT inherited keys", () => {
  test("canDo with an inherited op name is a plain false, not a TypeError", () => {
    for (const op of ["constructor", "toString", "__proto__", "hasOwnProperty"]) assert.equal(canDo("owner", op), false, op);
    assert.equal(canDo("owner", "post"), true);
  });
  test("openAccount rejects an inherited type name", () => {
    const L = new Ledger();
    let err = null; try { L.openAccount({ id: "x", type: "constructor" }); } catch (e) { err = e; }
    assert.ok(err && /unknown account type/.test(err.message));
    assert.equal(L.openAccount({ id: "bank", type: "asset" }).normal, "debit");
  });
});
