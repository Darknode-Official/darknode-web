// JWT quick tools: signatures checked against Node's crypto, and the auditor's
// handling of a non-numeric exp claim.

import crypto from "node:crypto";
import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as WEB } from "../../public/js/tools/websec.js";
import { TOOLS as APP } from "../../public/js/tools/appsec.js";

const b64u = (x) => Buffer.from(x).toString("base64url");
const jwt = (h, p, secret, bits = 256) => { const s = b64u(JSON.stringify(h)) + "." + b64u(JSON.stringify(p)); return s + "." + b64u(crypto.createHmac("sha" + bits, secret).update(s).digest()); };
const audit = (v) => WEB.find((t) => t.id === "w-jwt-analyzer").run(v, H);

group("JWT tools", () => {
  test("HS256 signer matches Node crypto, including non-ASCII payload and secret", async () => {
    const out = await APP.find((t) => t.id === "sx-jwt-hs256-sign").run({ payload: '{"n":"é 漢"}', secret: "pässwörd" }, H);
    const [h, p, s] = out.split(".");
    assert.equal(s, b64u(crypto.createHmac("sha256", "pässwörd").update(h + "." + p).digest()));
  });
  test("crack mode recovers a weak secret for HS256, HS384 and HS512", async () => {
    for (const bits of [256, 384, 512]) {
      const r = await audit({ token: jwt({ alg: "HS" + bits, typ: "JWT" }, { sub: "x" }, "secret", bits), mode: "crack" });
      assert.ok(/SECRET FOUND:\s+"secret"/.test(r), "HS" + bits);
    }
  });
  test("a string exp is reported, not shown as a missing claim", async () => {
    const r = await audit({ token: b64u('{"alg":"RS256"}') + "." + b64u('{"exp":"9999999999"}') + ".abc", mode: "analyze" });
    assert.ok(/exp is not a number/.test(r));
    assert.ok(/\[MEDIUM\] "exp" is "9999999999", not a NumericDate/.test(r));
    assert.notOk(/no exp claim/.test(r));
  });
});
