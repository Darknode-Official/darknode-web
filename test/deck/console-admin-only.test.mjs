// The Deck is the only signed-in UI for users; the AWS-style console is an admin-only
// option opened from the Admin page. auth.js decides this in browser-only code, so the
// rules are pinned against its source.

import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";

const src = (f) => readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8");
const auth = src("auth.js"), admin = src("admin.js");

group("deck: console is admin-only", () => {
  test("the console lives under /console and only admins get it there", () => {
    assert.ok(/return !\(_isAdmin && isConsolePath\(location\.pathname\)\);/.test(auth));
    assert.notOk(/localStorage\.getItem\(UI_PREF\)/.test(auth));
  });
  test("the console's own links are /console/<page>; embedded tool frames keep the bare path", () => {
    assert.ok(/const conBase = new URLSearchParams\(location\.search\)\.get\("embed"\) === "1" \? "" : CONSOLE_BASE;/.test(auth));
    assert.ok(/if \(p && isConsolePath\(p\)\) p = p\.slice\(CONSOLE_BASE\.length\);/.test(auth));
  });
  test("a non-admin on a /console link gets that page in the Deck", () => {
    assert.ok(/location\.pathname\.replace\(\/\^\\\/\(console\(\\\/\|\$\)\)\?\/, ""\)/.test(auth));
  });
  test("the Deck no longer offers users a switch to the console", () => {
    assert.ok(!/onClassic:/.test(auth));
  });
  test("a Deck that fails to load falls back to the console only for admins; users get a retry", () => {
    assert.ok(/if \(_isAdmin\) \{ _deckFailed = true; renderApp\(user\); return; \}/.test(auth));
    assert.ok(/Your workspace did not load/.test(auth) && /id="dkRetry"/.test(auth));
  });
  test("the Admin page carries the console button, and it opens /console in the top window", () => {
    assert.ok(/id="consoleLaunch">Open AWS console</.test(admin));
    assert.ok(/window\.top\.location\.assign\("\/console"\)/.test(admin));
    assert.notOk(/dn_ui/.test(admin.replace(/\/\/.*$/gm, "")));
  });
  test("desktop / ?app=1 guests get the Deck, not the console", () => {
    assert.notOk(/q\.get\("app"\) === "1" \|\| document\.documentElement/.test(auth));
    assert.notOk(/if \(sessionStorage\.getItem\("dn_guest"\) === "1"\) return false;/.test(auth));
  });
  test("?embed=1 opened directly in a tab by a non-admin drops to the Deck; the Deck's own tool frames keep it", () => {
    assert.ok(/if \(q\.get\("embed"\) === "1" && !_isAdmin && window\.parent === window\) \{ q\.delete\("embed"\);/.test(auth));
  });
});
