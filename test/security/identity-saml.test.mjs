// SAML Message Decoder quick tool (public/js/tools/identity.js, id-saml-decode): its pure-JS raw DEFLATE inflater.

import { test, assert, group } from "../harness.mjs";
import { deflateRawSync } from "node:zlib";
import { TOOLS } from "../../public/js/tools/identity.js";
import { H } from "../../public/js/tools/_helpers.js";

const run = (data, mode = "Auto-detect") => TOOLS.find((t) => t.id === "id-saml-decode").run({ data, mode }, H);
const XML = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" Version="2.0"><saml:Issuer>https://sp.test.darknode.ai</saml:Issuer>' + "<a>repeat</a>".repeat(100) + "</samlp:AuthnRequest>";

group("identity: SAML decoder inflate", () => {
  test("HTTP-Redirect value round-trips at every zlib level (stored, fixed and dynamic blocks)", () => {
    for (const level of [0, 1, 6, 9]) {
      const r = run(deflateRawSync(Buffer.from(XML), { level }).toString("base64"));
      assert.ok(typeof r === "string" && r.includes("sp.test.darknode.ai"), "level " + level);
    }
  });
  test("truncated or non-DEFLATE input returns an error instead of looping forever", () => {
    const full = deflateRawSync(Buffer.from(XML));
    assert.ok(run(full.subarray(0, full.length >> 1).toString("base64"), "HTTP-Redirect (inflate)").error);
    assert.ok(run("constructor").error);
    assert.ok(run("AAAA").error);
  });
});
