// Unit tests for public/js/core/export.js (pure parts; download() is browser-only)
import { test, group, assert } from "../harness.mjs";
import { toCsv, toJson, toNdjson, fileStamp, toIcs, icsFold, zipFiles, crc32, download } from "../../public/js/core/export.js";

const rd16 = (b, o) => b[o] | (b[o + 1] << 8);
const rd32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const txt = (b, o, n) => new TextDecoder().decode(b.subarray(o, o + n));

// Parse EOCD + central directory + local headers of a zip we wrote.
function parseZip(z) {
  let eocd = -1;
  for (let i = z.length - 22; i >= 0; i--) if (rd32(z, i) === 0x06054b50) { eocd = i; break; }
  assert.ok(eocd >= 0, "EOCD found");
  const count = rd16(z, eocd + 10), cdSize = rd32(z, eocd + 12), cdStart = rd32(z, eocd + 16);
  assert.equal(rd16(z, eocd + 8), count);
  assert.equal(cdStart + cdSize, eocd, "central dir ends at EOCD");
  const entries = [];
  let p = cdStart;
  for (let i = 0; i < count; i++) {
    assert.equal(rd32(z, p), 0x02014b50, "central header sig");
    const method = rd16(z, p + 10), crc = rd32(z, p + 16), csize = rd32(z, p + 20), usize = rd32(z, p + 24);
    const nlen = rd16(z, p + 28), elen = rd16(z, p + 30), clen = rd16(z, p + 32), local = rd32(z, p + 42);
    const name = txt(z, p + 46, nlen);
    assert.equal(rd32(z, local), 0x04034b50, "local header sig");
    assert.equal(rd16(z, local + 8), method);
    assert.equal(rd32(z, local + 14), crc);
    const lnlen = rd16(z, local + 26), lelen = rd16(z, local + 28);
    assert.equal(txt(z, local + 30, lnlen), name);
    const dataAt = local + 30 + lnlen + lelen;
    entries.push({ name, method, crc, csize, usize, data: z.subarray(dataAt, dataAt + csize) });
    p += 46 + nlen + elen + clen;
  }
  return entries;
}

group("export: toCsv", () => {
  test("header + RFC 4180 quoting", () => {
    const out = toCsv([{ a: 'He said "hi"', b: "x,y" }], ["a", "b"]);
    assert.equal(out, 'a,b\r\n"He said ""hi""","x,y"\r\n');
  });
  test("formula-injection guard prefixes = + - @", () => {
    const out = toCsv([{ a: "=SUM(1)", b: "+1", c: "-1", d: "@x" }], ["a", "b", "c", "d"]);
    assert.equal(out.split("\r\n")[1], "'=SUM(1),'+1,'-1,'@x");
  });
  test("arrays join with ; and null is empty", () => {
    assert.equal(toCsv([{ a: ["x", "y"], b: null }], ["a", "b"]).split("\r\n")[1], "x;y,");
  });
});

group("export: json / ndjson / stamp", () => {
  test("toJson is 2-space pretty with trailing newline", () => {
    assert.equal(toJson({ a: 1 }), '{\n  "a": 1\n}\n');
  });
  test("toNdjson one row per line", () => {
    assert.equal(toNdjson([{ a: 1 }, { b: 2 }]), '{"a":1}\n{"b":2}\n');
  });
  test("fileStamp is YYYYMMDD-HHMM in local time", () => {
    assert.ok(/^\d{8}-\d{4}$/.test(fileStamp()));
    assert.equal(fileStamp(new Date(2026, 9, 16, 9, 5)), "20261016-0905");
  });
});

group("export: toIcs", () => {
  test("escapes , ; \\ and newlines", () => {
    const ics = toIcs([{ uid: "u1", start: "2026-10-16T09:00:00Z", summary: "a, b; c\\d", description: "l1\nl2", stamp: "2026-10-01T00:00:00Z" }]);
    assert.ok(ics.includes("SUMMARY:a\\, b\\; c\\\\d"), ics);
    assert.ok(ics.includes("DESCRIPTION:l1\\nl2"));
    assert.ok(ics.includes("DTSTART:20261016T090000Z"));
    assert.ok(ics.includes("DTSTAMP:20261001T000000Z"));
    assert.ok(ics.startsWith("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Darknode//Deck//EN"));
    assert.ok(ics.endsWith("END:VCALENDAR\r\n"));
  });
  test("all-day events use VALUE=DATE", () => {
    const ics = toIcs([{ uid: "u2", start: "2026-12-31", end: "2027-01-01", allDay: true, summary: "Contract end" }], { prodId: "-//T//X//EN" });
    assert.ok(ics.includes("DTSTART;VALUE=DATE:20261231"));
    assert.ok(ics.includes("DTEND;VALUE=DATE:20270101"));
    assert.ok(ics.includes("PRODID:-//T//X//EN"));
  });
  test("folds lines at 75 octets with space continuation", () => {
    const long = "x".repeat(200);
    const ics = toIcs([{ uid: "u3", start: "2026-10-16T09:00:00Z", summary: long }]);
    for (const line of ics.split("\r\n")) assert.ok(new TextEncoder().encode(line).length <= 75, "line <= 75 octets");
    assert.ok(ics.includes("\r\n x"), "continuation starts with space");
    const unfolded = ics.replace(/\r\n /g, "");
    assert.ok(unfolded.includes("SUMMARY:" + long));
  });
  test("icsFold never splits a multi-byte code point", () => {
    const s = "SUMMARY:" + "é".repeat(100);
    const folded = icsFold(s);
    assert.equal(folded.replace(/\r\n /g, ""), s);
    for (const line of folded.split("\r\n")) assert.ok(new TextEncoder().encode(line).length <= 75);
  });
});

group("export: zipFiles", () => {
  test("crc32 known vector", () => {
    assert.equal(crc32(new TextEncoder().encode("123456789")), 0xcbf43926);
    assert.equal(crc32(new Uint8Array(0)), 0);
  });
  test("stored archive has valid local headers, central dir and EOCD", async () => {
    const z = await zipFiles([{ name: "a.txt", text: "hello" }, { name: "dir/b.csv", text: "x,y\r\n1,2\r\n" }], { compress: false });
    const e = parseZip(z);
    assert.equal(e.length, 2);
    assert.deepEqual(e.map((x) => x.name), ["a.txt", "dir/b.csv"]);
    assert.equal(e[0].method, 0);
    assert.equal(e[0].usize, 5);
    assert.equal(e[0].csize, 5);
    assert.equal(e[0].crc, crc32(new TextEncoder().encode("hello")));
    assert.equal(new TextDecoder().decode(e[0].data), "hello");
    assert.equal(e[1].usize, 10);
  });
  test("bytes input and empty file store fine", async () => {
    const z = await zipFiles([{ name: "bin", bytes: Uint8Array.from([1, 2, 3]) }, { name: "empty", text: "" }], { compress: false });
    const e = parseZip(z);
    assert.equal(e[0].usize, 3);
    assert.equal(e[1].usize, 0);
    assert.equal(e[1].crc, 0);
  });
  test("compress path deflates when the runtime supports deflate-raw", async () => {
    let supported = true;
    try { new CompressionStream("deflate-raw"); } catch (_) { supported = false; }
    const text = "abc".repeat(2000);
    const z = await zipFiles([{ name: "r.txt", text }], { compress: true });
    const [e] = parseZip(z);
    assert.equal(e.usize, 6000);
    assert.equal(e.crc, crc32(new TextEncoder().encode(text)));
    if (!supported) { assert.equal(e.method, 0); return; }
    assert.equal(e.method, 8);
    assert.ok(e.csize < e.usize, "compressed smaller than stored");
    const ds = new DecompressionStream("deflate-raw");
    const back = await new Response(new Blob([e.data]).stream().pipeThrough(ds)).text();
    assert.equal(back, text);
  });
});

group("export: download", () => {
  test("throws outside a browser", () => {
    assert.throws(() => download("x.txt", "x"));
  });
});
