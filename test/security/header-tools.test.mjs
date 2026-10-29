// HSTS parser and Set-Cookie analyzer. The HSTS parser missed a quoted max-age
// (valid per RFC 6797) and read the first of repeated directives, which makes a
// browser ignore the whole header. The cookie analyzer never checked the
// __Secure-/__Host- prefix rules, so a cookie the browser drops was reported as
// fine, and SameSite=None without Secure (also dropped) was only informational.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as APPSEC } from "../../public/js/tools/appsec.js";
import { TOOLS as WEBSEC } from "../../public/js/tools/websec.js";

const hsts = (h) => APPSEC.find((t) => t.id === "sx-hsts-parser").run({ h }, H);
const cookie = (c) => WEBSEC.find((t) => t.id === "w-set-cookie-analyzer").run({ cookie: c }, H);

group("sx-hsts-parser: RFC 6797 directive parsing", () => {
  test("a quoted max-age is read", () => {
    const r = hsts('max-age="31536000"; includeSubDomains; preload');
    assert.ok(/max-age: 31536000 s/.test(r) && !/invalid/i.test(r), r);
  });
  test("a repeated directive makes the header invalid", () => {
    assert.ok(/INVALID: max-age appears more than once/.test(hsts("max-age=31536000; max-age=1")));
  });
  test("max-age=0 is explained as turning HSTS off", () => {
    assert.ok(/forget HSTS/.test(hsts("max-age=0")));
  });
});

group("w-set-cookie-analyzer: cookie name prefixes", () => {
  test("__Host- with Domain and a non-root Path is rejected", () => {
    assert.ok(/FAIL __Host- prefix requires no Domain attribute, Path=\//.test(cookie("__Host-sid=1; Path=/app; Secure; Domain=x.test")));
  });
  test("__Secure- without Secure is rejected, matched case-insensitively", () => {
    assert.ok(/FAIL __secure- prefix requires Secure/.test(cookie("__secure-a=1")));
  });
  test("a correct __Host- cookie passes", () => {
    assert.ok(/OK   __Host- prefix rules met/.test(cookie("__Host-sid=1; Path=/; Secure; HttpOnly; SameSite=Lax")));
  });
  test("SameSite=None without Secure is a warning", () => {
    assert.ok(/WARN SameSite=None without Secure/.test(cookie("a=1; SameSite=None")));
  });
});
