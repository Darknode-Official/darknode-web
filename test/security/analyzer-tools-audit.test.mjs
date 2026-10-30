// Regression tests for the Deck analyzer-tool audit (2026-10-30): security.txt
// Expires, steganography container walking, binary analyzer PE/ELF/x86/IoC
// helpers, malware classifier YARA + PE header, memory forensics hex/tree,
// crypto tools Morse/Base85/number-base. Each test pins a reproduced bug.
// encoding-suite.js runs a location/licence check at import time and
// forensics-toolkit.js keeps its helpers inside the render closure, so their
// fixes are covered by the repro scripts only.

import { test, assert, group } from "../harness.mjs";
import { validateSecurityTxt } from "../../public/js/security-txt.js";
import { detectFileType, findAppendedData, readImageMetadata } from "../../public/js/steganography.js";
import { parsePE, parseELF, disassemble, extractIoCs, generateYARA } from "../../public/js/binary-analyzer.js";
import { scanCustomYara, parsePEHeaders, findImports, extractIOCs } from "../../public/js/malware-classifier.js";
import { parseHexInput, buildProcessTree } from "../../public/js/memory-forensics.js";
import { morseToText, base85Decode, parseBigIntInBase } from "../../public/js/crypto-tools.js";

const crc32 = (b) => { let crc = 0xffffffff; for (const x of b) { let c = (crc ^ x) & 0xff; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crc = (crc >>> 8) ^ c; } return (crc ^ 0xffffffff) >>> 0; };
const chunk = (type, data) => { const l = Buffer.alloc(4); l.writeUInt32BE(data.length); const td = Buffer.concat([Buffer.from(type), data]); const c = Buffer.alloc(4); c.writeUInt32BE(crc32(td)); return Buffer.concat([l, td, c]); };
const PNG_SIG = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
function png(idat, tail) {
  const ihdr = Buffer.alloc(13); ihdr.writeUInt32BE(1, 0); ihdr.writeUInt32BE(1, 4); ihdr[8] = 8; ihdr[9] = 2;
  return new Uint8Array(Buffer.concat([PNG_SIG, chunk("IHDR", ihdr), chunk("IDAT", idat), chunk("IEND", Buffer.alloc(0)), tail || Buffer.alloc(0)]));
}
const timed = (fn) => { const t = Date.now(); fn(); return Date.now() - t; };

group("security-txt", () => {
  test("Expires must be an RFC 3339 date-time", () => {
    const errs = (exp) => validateSecurityTxt("Contact: mailto:test@darknode.ai\nExpires: " + exp + "\n").findings.map((f) => f.msg).join("\n");
    for (const bad of ["Fri, 01 Jan 2027 00:00:00 GMT", "12/01/2027", "2027", "2027-12-01"]) assert.ok(/RFC 3339/.test(errs(bad)), bad);
    assert.ok(!/RFC 3339/.test(errs("2027-12-01T00:00:00Z")));
    assert.ok(!/RFC 3339/.test(errs("2027-12-01T00:00:00.5+02:00")));
  });
});

group("steganography", () => {
  test("empty file is not detected as JPEG", () => {
    assert.equal(detectFileType(new Uint8Array(0)), null);
  });
  test("FF D9 inside PNG IDAT is not appended data; bytes after IEND are", () => {
    assert.equal(findAppendedData(png(Buffer.from([0x78, 0x9c, 0xff, 0xd9, 1, 2]))), null);
    const r = findAppendedData(png(Buffer.from([0x78, 0x9c, 1, 2]), Buffer.from("PK\x03\x04secret")));
    assert.ok(r && r.size === 10, JSON.stringify(r));
  });
  test("PNG chunk length 0xFFFFFFF4 does not loop forever", () => {
    const evil = new Uint8Array(Buffer.concat([PNG_SIG, Buffer.from([0xff, 0xff, 0xff, 0xf4]), Buffer.from("abcd"), Buffer.alloc(16)]));
    assert.ok(Array.isArray(readImageMetadata(evil)));
  });
  test("BMP and RIFF report bytes past their declared size", () => {
    const bmp = Buffer.alloc(20); bmp.write("BM"); bmp.writeUInt32LE(14, 2);
    assert.equal(findAppendedData(new Uint8Array(bmp)).size, 6);
    const riff = Buffer.alloc(16); riff.write("RIFF"); riff.writeUInt32LE(8, 4); riff.write("WEBP", 8);
    assert.equal(findAppendedData(new Uint8Array(riff)), null);
  });
});

group("binary-analyzer", () => {
  test("truncated PE header is marked invalid instead of crashing the overview", () => {
    const mz = Buffer.alloc(64); mz.write("MZ"); mz.writeUInt32LE(0x1000, 0x3c);
    assert.equal(parsePE(new Uint8Array(mz)).valid, false);
  });
  test("PE32+ ImageBase reads all 8 bytes", () => {
    const p = Buffer.alloc(0x400); p.write("MZ"); p.writeUInt32LE(0x80, 0x3c); p.write("PE\0\0", 0x80);
    p.writeUInt16LE(0x8664, 0x84); p.writeUInt16LE(240, 0x94); p.writeUInt16LE(0x20b, 0x98); p.writeBigUInt64LE(0x140000000n, 0x98 + 24);
    assert.equal(parsePE(new Uint8Array(p)).optionalHeader.imageBase.toString(16), "140000000");
  });
  test("ELF64: big-endian header + program header, and entry above 4 GiB", () => {
    const e = Buffer.alloc(256); e.write("\x7fELF", 0, "latin1"); e[4] = 2; e[5] = 2; e[6] = 1;
    e.writeUInt16BE(2, 16); e.writeUInt16BE(21, 18); e.writeUInt32BE(1, 20);
    e.writeBigUInt64BE(0x10000500n, 24); e.writeBigUInt64BE(64n, 32);
    e.writeUInt16BE(64, 52); e.writeUInt16BE(56, 54); e.writeUInt16BE(1, 56); e.writeUInt32BE(0x6474e551, 64); e.writeUInt32BE(6, 68);
    const el = parseELF(new Uint8Array(e));
    assert.equal(el.header.entryPoint.toString(16), "10000500");
    assert.equal(el.programHeaders[0].typeName, "GNU_STACK");
    const k = Buffer.alloc(128); k.write("\x7fELF", 0, "latin1"); k[4] = 2; k[5] = 1; k.writeBigUInt64LE(0xffffffff81000000n, 24);
    assert.equal(parseELF(new Uint8Array(k)).header.entryPoint.toString(16), "ffffffff81000000");
  });
  test("ModRM immediates are read after the ModRM byte", () => {
    const ops = disassemble(Uint8Array.from([0x83, 0xc0, 0x05, 0xc7, 0xc0, 0x78, 0x56, 0x34, 0x12]), 0, 5).map((x) => x.operands);
    assert.ok(/0x5$/.test(ops[0]) && /0x12345678$/.test(ops[1]), ops.join(" ; "));
  });
  test("ModRM SIB + displacement is skipped before the immediate", () => {
    const d = disassemble(Uint8Array.from([0x83, 0x44, 0x24, 0x08, 0x05, 0x90]), 0, 5);
    assert.ok(/0x5$/.test(d[0].operands) && d[1].mnemonic === "NOP", JSON.stringify(d));
  });
  test("jump targets above 4 GiB are not truncated", () => {
    assert.equal(disassemble(Uint8Array.from([0xeb, 0x00]), 0x140001000, 1)[0].operands, "0x140001002");
  });
  test("generated YARA rule is valid with a digit-leading name and no strings", () => {
    const y = generateYARA("1.exe", [], new Uint8Array(4));
    assert.ok(/^rule _1_exe/m.test(y) && !/strings:/.test(y) && /filesize == 4/.test(y), y);
  });
  test("IoC regexes stay linear on a long dotted run", () => {
    assert.ok(timed(() => extractIoCs([{ value: "a.".repeat(50000), offset: 0 }])) < 2000);
  });
});

group("malware-classifier", () => {
  const bytes = new TextEncoder().encode("hello world");
  test("YARA condition does not resolve inherited string ids", () => {
    assert.ok(/undefined string/.test(scanCustomYara('rule r { strings: $a = "zzz" condition: $toString }', bytes)[0].error || ""));
    const r = scanCustomYara('rule r { strings: $a = "zzz" condition: #constructor == 1 }', bytes)[0];
    assert.ok(!r.matched && /undefined string/.test(r.error || ""));
  });
  test("PE TimeDateStamp and entry point are unsigned", () => {
    const p = Buffer.alloc(0x200); p.write("MZ"); p.writeUInt32LE(0x80, 0x3c); p.write("PE\0\0", 0x80);
    p.writeUInt16LE(0x14c, 0x84); p.writeUInt32LE(0x9a2b3c4d, 0x88); p.writeUInt16LE(224, 0x94); p.writeUInt16LE(0x10b, 0x98); p.writeUInt32LE(0x80001000, 0x80 + 40);
    const h = parsePEHeaders(new Uint8Array(p));
    assert.equal(h.compileDate, new Date(0x9a2b3c4d * 1000).toISOString());
    assert.equal(h.entryPoint, "0x80001000");
  });
  test("API names match whole identifiers only", () => {
    assert.equal(JSON.stringify(findImports(null, [{ str: "std::filesystem error" }, { str: "closesocket" }])), "{}");
  });
  test("email IOC regex stays linear on a long dotted run", () => {
    assert.ok(timed(() => extractIOCs([{ str: "a.".repeat(50000) }])) < 2000);
  });
});

group("memory-forensics", () => {
  test("0x-prefixed hex bytes parse as bytes", () => {
    assert.deepEqual(Array.from(parseHexInput("0x4D 0x5A 0x90 0x00")), [0x4d, 0x5a, 0x90, 0]);
  });
  test("YARA scan honours the condition (shared evaluator)", () => {
    const rule = 'rule r {\n strings:\n  $mz = { 4D 5A }\n  $dos = "This program"\n condition:\n  $mz at 0 and $dos\n}';
    assert.equal(scanCustomYara(rule, parseHexInput("00004D5A"))[0].matched, false);
    assert.equal(scanCustomYara(rule, parseHexInput("4D5A00" + Buffer.from("This program").toString("hex")))[0].matched, true);
  });
  test("parent cycles do not hide processes from the tree", () => {
    assert.equal(buildProcessTree([{ pid: 4, ppid: 4, name: "x" }]).length, 1);
    const roots = buildProcessTree([{ pid: 10, ppid: 20 }, { pid: 20, ppid: 10 }, { pid: 30, ppid: 10 }]);
    const seen = new Set(); const walk = (n) => { seen.add(n.pid); n.children.forEach(walk); }; roots.forEach(walk);
    assert.equal(seen.size, 3);
  });
});

group("crypto-tools", () => {
  test("Morse decode does not resolve inherited keys", () => {
    assert.equal(morseToText("... --- ... toString constructor"), "SOS??");
  });
  test("Base85 rejects a group above 2^32-1", () => {
    assert.throws(() => base85Decode("uuuuu"));
    assert.deepEqual(Array.from(base85Decode("s8W-!")), [255, 255, 255, 255]);
  });
  test("number-base prefix is stripped only for its own base", () => {
    assert.equal(parseBigIntInBase("0b1", 16), 0xb1n);
    assert.equal(parseBigIntInBase("-0xff", 16), -255n);
    assert.equal(parseBigIntInBase("0b101", 2), 5n);
    assert.throws(() => parseBigIntInBase("-", 10));
  });
});
