// Crypto quick tools audit: each test reproduces a bug found by running the tool against
// Node crypto, OpenSSL output or a hand-checked value, and pins the fix.

import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/crypto.js";

const run = async (id, v) => { try { const r = await TOOLS.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };

group("crypto quick tools audit", () => {
  test("JWK to PEM accepts keys tagged for another use (alg RSA-OAEP-256, use enc)", async () => {
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const jwk = { ...rsa.publicKey.export({ format: "jwk" }), alg: "RSA-OAEP-256", use: "enc" };
    const r = await run("cr-jwk-to-pem", { jwk: JSON.stringify(jwk) });
    assert.equal(r.trim(), rsa.publicKey.export({ type: "spki", format: "pem" }).trim());
  });
  test("RSA-PSS verify accepts a max-salt signature (the OpenSSL/Node default)", async () => {
    const rsa = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const sig = crypto.sign("sha256", Buffer.from("msg"), { key: rsa.privateKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING });
    const pem = rsa.publicKey.export({ type: "spki", format: "pem" });
    assert.ok(/^VALID/.test(await run("cr-rsa-verify", { pem, msg: "msg", sig: sig.toString("base64"), scheme: "PSS", hash: "SHA-256" })));
    assert.ok(/^INVALID/.test(await run("cr-rsa-verify", { pem, msg: "msg!", sig: sig.toString("base64"), scheme: "PSS", hash: "SHA-256" })));
  });
  test("ASN.1 decoder reports truncated DER and shows negative INTEGERs", async () => {
    assert.ok(/truncated/.test(await run("cr-asn1-decode", { data: "30" })));
    assert.ok(/exceeds/.test(await run("cr-asn1-decode", { data: "3082" })));
    assert.ok(/INTEGER len=1 {2}-128$/.test(await run("cr-asn1-decode", { data: "020180" })));
  });
  test("DER/PEM converter returns an error for a malformed base64 body instead of throwing", async () => {
    assert.ok(/malformed/.test(await run("cr-pem-wrap", { mode: "PEM to DER", data: "-----BEGIN X-----\nabcde\n-----END X-----" })));
  });
  test("extended gcd reports a non-negative gcd for negative inputs", async () => {
    const r = await run("cr-ext-gcd", { a: "4", b: "-6" });
    assert.ok(/^gcd = 2\n/.test(r) && /= 2$/.test(r));
  });
  test("primality test does not call 0 and 1 composite", async () => {
    assert.ok(/neither prime nor composite/.test(await run("cr-primality-test", { n: "1", rounds: "8" })));
  });
  test("RSA with n = p^2 uses phi = p(p-1)", async () => {
    const c = String((65n ** 17n) % 3721n);
    assert.ok(/\nm = 65\n/.test(await run("cr-rsa-decrypt-pq", { p: "61", q: "61", e: "17", c })));
    assert.ok(/phi\(n\) {2}= 3660/.test(await run("cr-rsa-compute-d", { p: "61", q: "61", e: "17" })));
  });
  test("ECDSA nonce-reuse with n = 0 is an error, not a division-by-zero throw", async () => {
    assert.ok(/must be >= 2/.test(await run("cr-ecdsa-nonce-reuse", { n: "0", r: "1", s1: "2", s2: "3", h1: "4", h2: "5" })));
  });
  test("Vigenere key length ranks the key length above its multiples", async () => {
    const txt = "Cryptography is the practice and study of techniques for secure communication in the presence of adversarial behavior. More generally, cryptography is about constructing and analyzing protocols that prevent third parties or the public from reading private messages. Modern cryptography exists at the intersection of the disciplines of mathematics, computer science, information security, electrical engineering, digital signal processing, physics, and others.";
    const ct = txt.toUpperCase().replace(/[^A-Z]/g, "").split("").map((c, i) => String.fromCharCode((c.charCodeAt(0) - 65 + "KEY".charCodeAt(i % 3) - 65) % 26 + 65)).join("");
    assert.ok(/Best guesses: 3,/.test(await run("cr-vigenere-keylen", { text: ct })));
  });
  test("key strength does not claim ~0-bit security for RSA below 1024 bits", async () => {
    assert.ok(/Security level: {2}<80-bit/.test(await run("cr-key-strength", { type: "RSA/DH (modulus bits)", size: "512" })));
  });
  test("repeating-XOR breaker treats a negative key length as auto", async () => {
    const ct = Buffer.from("Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal").map((b, i) => b ^ "ICE".charCodeAt(i % 3));
    assert.ok(!/THROW/.test(await run("cr-repeating-xor-break", { data: ct.toString("hex"), fmt: "hex", keylen: "-3" })));
  });
  test("RSA decrypt from p,q still refuses an e that is not invertible mod phi", async () => {
    assert.ok(/gcd\(e, phi\) != 1/.test(await run("cr-rsa-decrypt-pq", { p: "61", q: "53", e: "6", c: "5" })));
  });
});
