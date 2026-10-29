// Crypto quick tools checked against Node's crypto, and strict hex input: text
// typed into a hex field is an error, not silently different bytes.

import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/crypto.js";
import { TOOLS as FX } from "../../public/js/tools/forensics.js";

const run = async (id, v) => { try { const r = await TOOLS.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };
const hx = (b) => Buffer.from(b).toString("hex");
const KEY = "000102030405060708090a0b0c0d0e0f", IV = "cafebabefacedbaddecaf888";

group("crypto quick tools", () => {
  test("AES-GCM with AAD matches Node", async () => {
    const c = crypto.createCipheriv("aes-128-gcm", Buffer.from(KEY, "hex"), Buffer.from(IV, "hex"));
    c.setAAD(Buffer.from("feedface", "hex"));
    const want = hx(Buffer.concat([c.update("hello"), c.final(), c.getAuthTag()]));
    assert.ok((await run("cr-aes-gcm-encrypt", { key: KEY, iv: IV, pt: "hello", aad: "fe:ed:fa:ce" })).includes(want));
    assert.ok((await run("cr-aes-gcm-decrypt", { key: KEY, iv: IV, ct: want, aad: "feedface" })).includes("hello"));
  });
  test("text in a hex field is rejected, not reduced to its hex-looking letters", async () => {
    assert.ok(/not valid hex/i.test(await run("cr-aes-gcm-encrypt", { key: KEY, iv: IV, pt: "hello", aad: "hdr" })));
    assert.ok(/not valid hex/i.test(await run("cr-hkdf", { ikm: "my passphrase", salt: "", info: "", hash: "SHA-256", len: "256" })));
    assert.ok(/odd number/i.test(await run("cr-aes-cbc-encrypt", { key: KEY, iv: "abc", pt: "x" })));
  });
  test("HKDF and ChaCha20 match Node", async () => {
    const ikm = "0b".repeat(22), salt = "000102030405060708090a0b0c";
    const want = hx(crypto.hkdfSync("sha256", Buffer.from(ikm, "hex"), Buffer.from(salt, "hex"), Buffer.from("ctx"), 42));
    assert.ok((await run("cr-hkdf", { ikm, salt, info: "ctx", hash: "SHA-256", len: "336" })).includes(want));
    const key = "11".repeat(32), nonce = "22".repeat(12), iv = Buffer.alloc(16); iv.writeUInt32LE(1, 0); Buffer.from(nonce, "hex").copy(iv, 4);
    const c = crypto.createCipheriv("chacha20", Buffer.from(key, "hex"), iv), msg = "a message longer than one 64-byte ChaCha20 block, to cross a block edge";
    assert.ok((await run("cr-chacha20", { key, nonce, counter: "1", data: msg, mode: "Encrypt (text -> hex)" })).includes(hx(Buffer.concat([c.update(msg), c.final()]))));
  });
  test("shared H.fromHex and the forensics hex parser are strict too", async () => {
    assert.equal(hx(H.fromHex("de:ad be-ef")), "deadbeef");
    assert.equal(hx(H.fromHex("\\x41\\x42")), "4142");
    assert.throws(() => H.fromHex("hello"));
    assert.throws(() => H.fromHex("abc"));
    let r; try { r = await FX.find((t) => t.id === "fx-magic-bytes").run({ hex: "not hex at all", fmt: "Hex" }, H); } catch (e) { r = { error: e.message }; }
    assert.ok(r && /not valid hex/i.test(r.error));
  });
});
