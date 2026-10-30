// Binary-triage quick tools checked against ground truth: the PE/COFF spec, GNU strings,
// decodeURIComponent and hand-computed values.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/bininspect.js";

const run = async (id, v) => { try { const r = await TOOLS.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };

group("bininspect quick tools", () => {
  test("section flags show MEM_WRITE (bit 31) for a writable .data section", async () => {
    const r = await run("bi-pe-section-flags", { val: "0xC0000040" });
    assert.ok(r.includes("MEM_WRITE (0x80000000)"), r);
    assert.ok(r.includes("MEM_READ (0x40000000)"));
  });
  test("an RVA past a section's raw data has no file offset", async () => {
    const sections = ".text,0x1000,0x5000,0x400,0x5000\n.data,0x6000,0x2000,0x5400,0x1000\n.rsrc,0x8000,0x1000,0x6400,0x1000";
    const r = await run("bi-pe-rva-offset", { sections, value: "0x7500", dir: "RVA -> File offset" });
    assert.ok(/no file offset/.test(r) && !r.includes("0x6900"), r);
    assert.ok((await run("bi-pe-rva-offset", { sections, value: "0x6010", dir: "RVA -> File offset" })).includes("file offset 0x5410"));
  });
  test("blank integer input gives no output instead of 0x00000000", async () => {
    assert.equal(await run("bi-hex-int", { val: "", dir: "Integer -> Hex", width: "32-bit", signed: false }), "");
    assert.equal(await run("bi-hex-int", { val: "-1", dir: "Integer -> Hex", width: "32-bit", signed: false }), "0xffffffff  (32-bit)");
  });
  test("strings keeps tabs inside a string, like GNU strings", async () => {
    const data = Buffer.from("\x00\x01hello\tworld\x00").toString("hex");
    assert.equal(await run("bi-strings", { data, fmt: "Hex", min: 4, mode: "ASCII" }), "0x00000002  hello\tworld");
  });
  test("URL de-obfuscator still decodes when the value also has a stray %", async () => {
    const r = await run("bi-url-deobfuscate", { url: "q=100% sure&p=%252e%252e%252fetc", plus: false });
    assert.ok(r.includes("q=100% sure&p=../etc"), r);
    assert.ok(r.startsWith("decoded (2 layers)"));
  });
  test("bare hex code lists decode as hex, decimal lists as decimal", async () => {
    assert.equal(await run("bi-charcode-decode", { text: "68 65 6c 6c 6f" }), "hello");
    assert.equal(await run("bi-charcode-decode", { text: "104,101,108,108,111" }), "hello");
  });
  test("opcode lookup accepts 0x0F05 as advertised", async () => {
    assert.ok((await run("bi-x86-opcode", { q: "0x0F05" })).includes("SYSCALL"));
    assert.ok((await run("bi-x86-opcode", { q: "0f 05" })).includes("SYSCALL"));
  });
});
