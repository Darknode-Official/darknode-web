// Identity and hashing quick tools: inputs a real user pastes that used to give a wrong
// answer, a contradictory error, or a throw. Ground truth from Node's crypto and the specs.

import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as IDN } from "../../public/js/tools/identity.js";
import { TOOLS as HSH } from "../../public/js/tools/hashing.js";

const ALL = [...IDN, ...HSH];
const run = async (id, v) => { try { const r = await ALL.find((t) => t.id === id).run(v, H); return typeof r === "string" ? r : JSON.stringify(r); } catch (e) { return "THROW " + e.message; } };
const SECRET = H.base32encode("12345678901234567890"); // RFC 4226 test key
const hotp = (counter) => { const c = Buffer.alloc(8); c.writeBigUInt64BE(counter); const h = crypto.createHmac("sha1", "12345678901234567890").update(c).digest(); return String((h.readUInt32BE(h[19] & 15) & 0x7fffffff) % 1e6).padStart(6, "0"); };

group("identity + hashing quick tools audit", () => {
  test("PKCE S256 and HOTP still match RFC 7636 / RFC 4226", async () => {
    assert.ok((await run("id-pkce", { verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", method: "S256" })).includes("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    assert.ok((await run("id-hotp", { secret: SECRET.toLowerCase(), counter: "9", digits: "6", algo: "SHA-1" })).includes("HOTP: 520489"));
  });
  test("HOTP counter above 2^53 is used exactly, above 2^64 is refused", async () => {
    const big = 9007199254740993n;
    const r = await run("id-hotp", { secret: SECRET, counter: String(big), digits: "6", algo: "SHA-1" });
    assert.ok(r.includes("HOTP: " + hotp(big)) && r.includes(String(big)), r);
    assert.ok(/64 bits/.test(await run("id-hotp", { secret: SECRET, counter: "18446744073709551616", digits: "6", algo: "SHA-1" })));
  });
  test("authData flags accepts 0x45 and rejects base64", async () => {
    assert.ok((await run("id-authdata-flags", { hex: "0x45" })).includes("flags byte: 0x45"));
    const ad = "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630500000001";
    assert.ok((await run("id-authdata-flags", { hex: ad })).includes("flags byte: 0x05"));
    assert.ok(/not valid hex/i.test(await run("id-authdata-flags", { hex: Buffer.from(ad + "00", "hex").toString("base64") })));
  });
  test("objectGUID accepts a 0x prefix", async () => {
    assert.ok((await run("id-objectguid-decode", { hex: "0xD13C2E4B5A6F7E8F9A0B1C2D3E4F5061" })).includes("4b2e3cd1-6f5a-8f7e-9a0b-1c2d3e4f5061"));
  });
  test("PHC parser reads passlib's bare rounds field as rounds, not the salt", async () => {
    const r = await run("id-phc-parse", { hash: "$pbkdf2-sha256$29000$N2bMWWuNsfa.ZwCXdUHqrQ$WEJ9oz1PmSUwhbeTxIEwIWVfm8ox2oK4rf/3AE1sVhA" });
    assert.ok(/param rounds\s+29000/.test(r) && /salt \(b64\)\s+N2bMWWuNsfa\.ZwCXdUHqrQ/.test(r), r);
  });
  test("htpasswd SHA-crypt hashes are not called plaintext", async () => {
    assert.ok((await run("id-htpasswd-parse", { line: "u:$6$rounds=5000$salt$hash" })).includes("sha512crypt"));
    assert.ok((await run("id-htpasswd-parse", { line: "u:$5$salt$hash" })).includes("sha256crypt"));
  });
  test("otpauth URI with a stray % does not throw", async () => {
    const r = await run("id-otpauth-parse", { uri: "otpauth://totp/50%off:test@darknode.ai?secret=JBSWY3DPEHPK3PXP" });
    assert.ok(!r.startsWith("THROW") && r.includes("JBSWY3DPEHPK3PXP"), r);
  });
  test("shadow line with an out-of-range day count does not throw", async () => {
    const r = await run("id-shadow-parse", { line: "u:!:999999999:0:99999:7:::" });
    assert.ok(!r.startsWith("THROW") && r.includes("999999999"), r);
  });
  test("hash analyzer identifies a MySQL 4.1+ hash with its leading *", async () => {
    assert.ok((await run("h-hash-analyzer", { hash: "*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", mode: "identify" })).includes("MySQL4.1/5"));
  });
  test("ULID whose first character overflows 48 bits is rejected", async () => {
    assert.ok((await run("h-ulid-decode", { ulid: "01ARZ3NDEKTSV4RRFFQ69G5FAV" })).includes("1469922850259"));
    assert.ok(/first character/.test(await run("h-ulid-decode", { ulid: "8ZZZZZZZZZZZZZZZZZZZZZZZZZ" })));
  });
});
