// The Deck is the only signed-in UI for users; the AWS-style console is an admin-only
// option opened from the Admin page. auth.js decides this in browser-only code, so the
// rules are pinned against its source.

import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";

const src = (f) => readFileSync(new URL("../../public/js/" + f, import.meta.url), "utf8");
const auth = src("auth.js"), admin = src("admin.js");

group("deck: console is admin-only", () => {
  test("a saved dn_ui=console preference is honoured only for admins", () => {
    assert.ok(/return !\(_isAdmin && localStorage\.getItem\(UI_PREF\) === "console"\);/.test(auth));
  });
  test("the Deck no longer offers users a switch to the console", () => {
    assert.ok(!/onClassic:/.test(auth));
  });
  test("a Deck that fails to load falls back to the console only for admins; users get a retry", () => {
    assert.ok(/if \(_isAdmin\) \{ _deckFailed = true; renderApp\(user\); return; \}/.test(auth));
    assert.ok(/Your workspace did not load/.test(auth) && /id="dkRetry"/.test(auth));
  });
  test("the Admin page carries the console switch, and it reloads the top window", () => {
    assert.ok(/id="consoleLaunch">Open AWS console</.test(admin));
    assert.ok(/localStorage\.setItem\("dn_ui", "console"\)[\s\S]{0,80}window\.top\.location\.assign\("\/"\)/.test(admin));
  });
});
