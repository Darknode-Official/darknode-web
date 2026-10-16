// Unpack tests (public/js/ingest/unpack.js): hand-rolled zip reader, gzip via
// DecompressionStream, nesting, caps and refusals. Zips are built in-test from
// raw bytes so no fixtures are needed.

import { gzipSync, deflateRawSync } from "node:zlib";
import { test, assert, group } from "../harness.mjs";
import {
  unpack, unpackAll, unzip, gunzip, inflateRaw, canUnpack, isArchiveName, magic, sanitizePath,
} from "../../public/js/ingest/unpack.js";

const enc = new TextEncoder();
const txt = (s) => enc.encode(s);
const CAN = canUnpack();

// --- tiny zip writer -------------------------------------------------------
const CRC_T = new Uint32Array(256).map((_, n) => { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; return c >>> 0; });
function crc32(u8) { let c = 0xffffffff; for (const b of u8) c = CRC_T[(c ^ b) & 0xff] ^ (c >>> 8); return (c ^ 0xffffffff) >>> 0; }

/** entries: [{ name, data, method=0, flags=0x800, usize?, csize?, nameBytes? }] */
function buildZip(entries, { cdOffOverride } = {}) {
  const parts = [], central = [];
  let off = 0;
  for (const e of entries) {
    const data = e.data || new Uint8Array(0);
    const name = e.nameBytes || txt(e.name);
    const method = e.method ?? 0, flags = e.flags ?? 0x800;
    const raw = e.raw || data;
    const csize = e.csize ?? data.length, usize = e.usize ?? raw.length, crc = crc32(raw);
    const lh = new Uint8Array(30 + name.length), lv = new DataView(lh.buffer);
    lv.setUint32(0, 0x04034b50, true); lv.setUint16(4, 20, true); lv.setUint16(6, flags, true); lv.setUint16(8, method, true);
    lv.setUint32(14, crc, true); lv.setUint32(18, csize, true); lv.setUint32(22, usize, true); lv.setUint16(26, name.length, true);
    lh.set(name, 30);
    parts.push(lh, data);
    const ch = new Uint8Array(46 + name.length), cv = new DataView(ch.buffer);
    cv.setUint32(0, 0x02014b50, true); cv.setUint16(4, 20, true); cv.setUint16(6, 20, true); cv.setUint16(8, flags, true); cv.setUint16(10, method, true);
    cv.setUint32(16, crc, true); cv.setUint32(20, csize, true); cv.setUint32(24, usize, true); cv.setUint16(28, name.length, true);
    cv.setUint32(42, off, true); ch.set(name, 46);
    central.push(ch);
    off += lh.length + data.length;
  }
  const cdOff = off, cdSize = central.reduce((n, c) => n + c.length, 0);
  const eocd = new Uint8Array(22), ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true); ev.setUint16(8, entries.length, true); ev.setUint16(10, entries.length, true);
  ev.setUint32(12, cdSize, true); ev.setUint32(16, cdOffOverride ?? cdOff, true);
  const all = [...parts, ...central, eocd], out = new Uint8Array(all.reduce((n, p) => n + p.length, 0));
  let p = 0; for (const a of all) { out.set(a, p); p += a.length; }
  return out;
}

async function collect(gen) {
  const entries = [];
  for (;;) { const r = await gen.next(); if (r.done) return { entries, ret: r.value }; entries.push(r.value); }
}
async function rejects(p, re) {
  let err = null; try { await p; } catch (e) { err = e; }
  assert.ok(err instanceof Error, "expected an Error");
  if (re) assert.ok(re.test(err.message), `message ${JSON.stringify(err.message)} !~ ${re}`);
  return err;
}

// --- helpers ----------------------------------------------------------------
group("ingest: unpack helpers", () => {
  test("magic detects zip, gzip, null", () => {
    assert.equal(magic(new Uint8Array([0x50, 0x4b, 3, 4, 0])), "zip");
    assert.equal(magic(new Uint8Array([0x1f, 0x8b, 8])), "gzip");
    assert.equal(magic(txt("hello")), null);
    assert.equal(magic(new Uint8Array(0)), null);
    assert.equal(magic(new Uint8Array([0x1f, 0x8b]).buffer), "gzip");
  });
  test("isArchiveName", () => {
    assert.ok(isArchiveName("a.zip")); assert.ok(isArchiveName("A.ZIP")); assert.ok(isArchiveName("x.tar.gz")); assert.ok(isArchiveName("x.gzip"));
    assert.notOk(isArchiveName("x.tar")); assert.notOk(isArchiveName("zip")); assert.notOk(isArchiveName(""));
  });
  test("canUnpack reports booleans", () => {
    assert.equal(typeof CAN.zip, "boolean"); assert.equal(typeof CAN.gzip, "boolean"); assert.equal(typeof CAN.deflateRaw, "boolean");
    assert.ok(CAN.zip); assert.ok(CAN.gzip, "Node 20 should support gzip DecompressionStream");
  });
  test("sanitizePath strips .., leading slash, backslashes", () => {
    assert.deepEqual(sanitizePath("../../etc/passwd"), ["etc", "passwd"]);
    assert.deepEqual(sanitizePath("/abs/x.txt"), ["abs", "x.txt"]);
    assert.deepEqual(sanitizePath("dir\\sub\\f.txt"), ["dir", "sub", "f.txt"]);
    assert.deepEqual(sanitizePath("./a//b/./c"), ["a", "b", "c"]);
  });
});

// --- stored zips -------------------------------------------------------------
group("ingest: stored zip", () => {
  const zip = buildZip([
    { name: "a.txt", data: txt("alpha") },
    { name: "dir/", data: new Uint8Array(0) },
    { name: "dir/b.json", data: txt("{\"b\":2}") },
    { name: "dir/sub/c.csv", data: txt("x,y\n1,2") },
  ]);
  test("yields files with names, sizes, bytes, path; skips directories", async () => {
    const { entries, ret } = await collect(unzip(zip, { name: "t.zip" }));
    assert.deepEqual(entries.map((e) => e.name), ["a.txt", "dir/b.json", "dir/sub/c.csv"]);
    assert.deepEqual(entries.map((e) => e.size), [5, 7, 7]);
    assert.equal(entries[0].text(), "alpha");
    assert.deepEqual(JSON.parse(entries[1].text()), { b: 2 });
    assert.deepEqual(entries[2].path, ["dir", "sub", "c.csv"]);
    assert.ok(entries[0].bytes instanceof Uint8Array);
    assert.equal(entries[0].fromArchive, "t.zip");
    assert.deepEqual(ret, { skipped: [] });
  });
  test("accepts an ArrayBuffer", async () => {
    const { entries } = await collect(unzip(zip.buffer.slice(zip.byteOffset, zip.byteOffset + zip.byteLength)));
    assert.equal(entries.length, 3);
  });
  test("unpack dispatches zip by magic and names fromArchive", async () => {
    const { entries } = await collect(unpack(zip, { name: "x.zip" }));
    assert.equal(entries.length, 3);
    assert.equal(entries[2].fromArchive, "x.zip");
  });
  test("works with a trailing zip comment (EOCD scan)", async () => {
    const z = buildZip([{ name: "k.txt", data: txt("k") }]);
    const comment = txt("comment ".repeat(100));
    const out = new Uint8Array(z.length + comment.length); out.set(z); out.set(comment, z.length);
    new DataView(out.buffer).setUint16(z.length - 2, comment.length, true);
    const { entries } = await collect(unzip(out));
    assert.equal(entries[0].text(), "k");
  });
  test("utf-8 names (flag bit 11) and cp437/latin1 names", async () => {
    const z = buildZip([
      { name: "café.txt", data: txt("1"), flags: 0x800 },
      { name: "x", nameBytes: new Uint8Array([0x6e, 0xe9, 0x2e, 0x74, 0x78, 0x74]), data: txt("2"), flags: 0 },
    ]);
    const { entries } = await collect(unzip(z));
    assert.equal(entries[0].name, "café.txt");
    assert.equal(entries[1].name, "né.txt");
  });
  test("sanitizes ../ and backslash and absolute names", async () => {
    const z = buildZip([
      { name: "../../etc/passwd", data: txt("p") },
      { name: "win\\dir\\f.txt", data: txt("w") },
      { name: "/abs/root.txt", data: txt("r") },
    ]);
    const { entries } = await collect(unzip(z));
    assert.deepEqual(entries.map((e) => e.name), ["etc/passwd", "win/dir/f.txt", "abs/root.txt"]);
    assert.deepEqual(entries[1].path, ["win", "dir", "f.txt"]);
    assert.notOk(entries.some((e) => e.path.includes("..")));
  });
  test("not a zip / corrupt input throws clearly", async () => {
    await rejects(collect(unzip(txt("short"))), /too short/);
    const junk = new Uint8Array(64); junk.set([0x50, 0x4b, 3, 4]);
    await rejects(collect(unzip(junk)), /end-of-central-directory/);
  });
});

// --- deflate -----------------------------------------------------------------
group("ingest: deflated zip", () => {
  if (!CAN.deflateRaw) {
    test("deflate zip (skipped: no deflate-raw in this Node)", () => assert.ok(true));
    test("inflateRaw (skipped: no deflate-raw in this Node)", () => assert.ok(true));
  } else {
    const raw = txt("deflate me ".repeat(200));
    test("inflateRaw round-trips node deflateRawSync", async () => {
      const out = await inflateRaw(new Uint8Array(deflateRawSync(raw)));
      assert.equal(out.length, raw.length);
      assert.equal(new TextDecoder().decode(out), new TextDecoder().decode(raw));
    });
    test("method 8 entries inflate", async () => {
      const comp = new Uint8Array(deflateRawSync(raw));
      const z = buildZip([{ name: "big.txt", data: comp, raw, method: 8 }, { name: "s.txt", data: txt("s") }]);
      const { entries } = await collect(unzip(z));
      assert.equal(entries[0].size, raw.length);
      assert.ok(entries[0].text().startsWith("deflate me deflate me"));
      assert.equal(entries[1].text(), "s");
    });
  }
});

// --- gzip ------------------------------------------------------------------
group("ingest: gzip", () => {
  const json = txt(JSON.stringify({ ok: true, n: [1, 2, 3] }));
  test("gunzip round-trips node gzipSync", async () => {
    const out = await gunzip(new Uint8Array(gzipSync(json)));
    assert.deepEqual(JSON.parse(new TextDecoder().decode(out)), { ok: true, n: [1, 2, 3] });
  });
  test("unpack of a .json.gz yields one entry named without .gz", async () => {
    const { entries, ret } = await collect(unpack(new Uint8Array(gzipSync(json)), { name: "report.json.gz" }));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "report.json");
    assert.deepEqual(entries[0].path, ["report.json"]);
    assert.equal(entries[0].fromArchive, "report.json.gz");
    assert.deepEqual(JSON.parse(entries[0].text()), { ok: true, n: [1, 2, 3] });
    assert.deepEqual(ret.skipped, []);
  });
  test("unnamed gzip falls back to \"data\"", async () => {
    const { entries } = await collect(unpack(new Uint8Array(gzipSync(txt("z")))));
    assert.equal(entries[0].name, "data");
  });
  test("plain (non-archive) input is yielded as itself", async () => {
    const { entries } = await collect(unpack(txt("plain text"), { name: "notes.txt" }));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "notes.txt"); assert.equal(entries[0].text(), "plain text"); assert.equal(entries[0].fromArchive, "");
  });
});

// --- nesting ------------------------------------------------------------------
group("ingest: nested archives", () => {
  test(".xml.gz inside a stored zip is expanded with full path", async () => {
    const z = buildZip([{ name: "logs/app.xml.gz", data: new Uint8Array(gzipSync(txt("<a/>"))) }, { name: "readme.txt", data: txt("r") }]);
    const { entries } = await collect(unpack(z, { name: "outer.zip" }));
    assert.deepEqual(entries.map((e) => e.name), ["logs/app.xml", "readme.txt"]);
    assert.deepEqual(entries[0].path, ["logs", "app.xml"]);
    assert.equal(entries[0].text(), "<a/>");
    assert.equal(entries[0].fromArchive, "outer.zip/logs/app.xml.gz");
  });
  test(".zip inside .zip is expanded under its folder", async () => {
    const inner = buildZip([{ name: "a.txt", data: txt("A") }, { name: "d/b.txt", data: txt("B") }]);
    const z = buildZip([{ name: "sub/inner.zip", data: inner }]);
    const { entries } = await collect(unpack(z, { name: "outer.zip" }));
    assert.deepEqual(entries.map((e) => e.name), ["sub/a.txt", "sub/d/b.txt"]);
    assert.equal(entries[1].fromArchive, "outer.zip/sub/inner.zip");
    assert.equal(entries[1].text(), "B");
  });
  test("depth limit 2: a zip three levels deep is yielded as raw bytes", async () => {
    const deep = buildZip([{ name: "x.txt", data: txt("X") }]);
    const mid = buildZip([{ name: "deep.zip", data: deep }]);
    const z = buildZip([{ name: "mid.zip", data: mid }]);
    const { entries } = await collect(unpack(z, { name: "outer.zip" }));
    assert.equal(entries.length, 1);
    assert.equal(entries[0].name, "deep.zip");
    assert.equal(magic(entries[0].bytes), "zip");
  });
  test("a .gz-named member without gzip magic is passed through untouched", async () => {
    const z = buildZip([{ name: "fake.gz", data: txt("not gzip") }]);
    const { entries } = await collect(unpack(z));
    assert.equal(entries[0].name, "fake.gz"); assert.equal(entries[0].text(), "not gzip");
  });
});

// --- caps & refusals ---------------------------------------------------------
group("ingest: caps", () => {
  const three = buildZip([{ name: "1.txt", data: txt("one") }, { name: "2.txt", data: txt("two!!") }, { name: "3.txt", data: txt("three") }]);
  test("maxEntries: extra entries skipped and reported", async () => {
    const { entries, ret } = await collect(unzip(three, { maxEntries: 1 }));
    assert.equal(entries.length, 1);
    assert.deepEqual(ret.skipped.map((s) => s.name), ["2.txt", "3.txt"]);
    assert.ok(/entries/.test(ret.skipped[0].reason));
  });
  test("maxEntryBytes: oversized entry skipped, smaller kept", async () => {
    const { entries, ret } = await collect(unzip(three, { maxEntryBytes: 4 }));
    assert.deepEqual(entries.map((e) => e.name), ["1.txt"]);
    assert.equal(ret.skipped.length, 2);
    assert.ok(/over/.test(ret.skipped[0].reason));
  });
  test("maxTotalBytes: stops adding once the budget is spent", async () => {
    const { entries, ret } = await collect(unzip(three, { maxTotalBytes: 8 }));
    assert.deepEqual(entries.map((e) => e.name), ["1.txt", "2.txt"]);
    assert.deepEqual(ret.skipped.map((s) => s.name), ["3.txt"]);
  });
  test("unpackAll returns { entries, skipped }", async () => {
    const r = await unpackAll(three, { name: "t.zip", maxEntries: 2 });
    assert.equal(r.entries.length, 2);
    assert.deepEqual(r.skipped, [{ name: "3.txt", reason: "over 2 entries" }]);
  });
  test("unpackAll on a gzip entry over maxEntryBytes reports it", async () => {
    const r = await unpackAll(new Uint8Array(gzipSync(txt("0123456789"))), { name: "n.txt.gz", maxEntryBytes: 4 });
    assert.equal(r.entries.length, 0);
    assert.equal(r.skipped[0].name, "n.txt");
  });
  test("ratio guard: stored entry lying about usize is refused", async () => {
    const z = buildZip([{ name: "bomb.bin", data: txt("0123456789"), usize: 11 * 1024 * 1024 }]);
    await rejects(collect(unzip(z)), /zip bomb|ratio/);
  });
  test("ratio guard ignores small lying entries (usize <= 10 MB)", async () => {
    const z = buildZip([{ name: "small.bin", data: txt("0123456789"), usize: 5000 }]);
    const { entries } = await collect(unzip(z));
    assert.equal(entries[0].size, 10);
  });
});

group("ingest: refusals", () => {
  test("encrypted entry (flag bit 0) is refused", async () => {
    const z = buildZip([{ name: "secret.txt", data: txt("s"), flags: 0x801 }]);
    await rejects(collect(unzip(z)), /encrypted/);
  });
  test("zip64 sizes (0xFFFFFFFF) are refused", async () => {
    const z = buildZip([{ name: "huge.bin", data: txt("x"), usize: 0xffffffff, csize: 0xffffffff }]);
    await rejects(collect(unzip(z)), /zip64/);
  });
  test("zip64 EOCD offset marker is refused", async () => {
    const z = buildZip([{ name: "a", data: txt("x") }], { cdOffOverride: 0xffffffff });
    await rejects(collect(unzip(z)), /zip64/);
  });
  test("unsupported compression method names the method", async () => {
    const z = buildZip([{ name: "b.bz2", data: txt("x"), method: 12 }]);
    await rejects(collect(unzip(z)), /unsupported compression method 12/);
  });
  test("refusals surface through unpack() too", async () => {
    const z = buildZip([{ name: "e.txt", data: txt("x"), flags: 1 }]);
    await rejects(unpackAll(z), /encrypted/);
  });
});
