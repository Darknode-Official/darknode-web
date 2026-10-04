// Account-isolation tests for the per-user credential store (public/js/user-keys.js)
// and static regression guards for the Section-1 security fixes.
//
// The described bug: two different signed-in users on one browser could read the
// same API key, each believing it was their own. These tests prove the storage
// layer (window.dnKeys) never returns one account's key to another, that signed-out
// callers get nothing, and that the previously hardcoded/shared secrets are gone.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import vm from "node:vm";
import { test, assert, group } from "../harness.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const pub = join(here, "..", "..", "public");

// Load user-keys.js (a classic IIFE script) into an isolated VM context with a
// minimal localStorage + window, exactly as a browser would provide them.
function loadDnKeys() {
  const src = readFileSync(join(pub, "js", "user-keys.js"), "utf8");
  const store = new Map();
  const localStorage = {
    getItem: (k) => (store.has(k) ? store.get(k) : null),
    setItem: (k, v) => { store.set(String(k), String(v)); },
    removeItem: (k) => { store.delete(k); },
    key: (i) => Array.from(store.keys())[i] ?? null,
    get length() { return store.size; },
  };
  const sandbox = { window: {}, localStorage, console };
  sandbox.window.localStorage = localStorage;
  vm.createContext(sandbox);
  vm.runInContext(src, sandbox, { filename: "user-keys.js" });
  return { dnKeys: sandbox.window.dnKeys, win: sandbox.window, store };
}

group("user-keys: account isolation", () => {
  test("a second user cannot read the first user's key", () => {
    const { dnKeys, win } = loadDnKeys();
    win.__dnUid = "userA";
    dnKeys.set("dn_api_key", "dn_live_AAA");
    assert.equal(dnKeys.get("dn_api_key"), "dn_live_AAA", "A reads its own key");

    win.__dnUid = "userB";
    assert.equal(dnKeys.get("dn_api_key"), null, "B must NOT read A's key");

    dnKeys.set("dn_api_key", "dn_live_BBB");
    assert.equal(dnKeys.get("dn_api_key"), "dn_live_BBB", "B reads its own key");

    win.__dnUid = "userA";
    assert.equal(dnKeys.get("dn_api_key"), "dn_live_AAA", "A still sees only A's key");
  });

  test("signed-out callers cannot read or persist keys", () => {
    const { dnKeys, win, store } = loadDnKeys();
    win.__dnUid = null;
    assert.equal(dnKeys.get("dn_api_key"), null, "no uid -> no read");
    assert.equal(dnKeys.set("dn_api_key", "leak"), false, "no uid -> write dropped");
    assert.equal(store.size, 0, "nothing was persisted while signed out");
  });

  test("JSON key maps are isolated per account", () => {
    const { dnKeys, win } = loadDnKeys();
    win.__dnUid = "userA";
    dnKeys.setJSON("dn_api_keys", { anthropic: "sk-ant-A", shodan: "shodanA" });
    win.__dnUid = "userB";
    assert.deepEqual(dnKeys.getJSON("dn_api_keys"), {}, "B sees an empty map, not A's providers");
    dnKeys.setJSON("dn_api_keys", { openai: "sk-B" });
    win.__dnUid = "userA";
    assert.deepEqual(dnKeys.getJSON("dn_api_keys"), { anthropic: "sk-ant-A", shodan: "shodanA" }, "A's map is intact and unseen by B");
  });

  test("namespaced keys do not collide across the known credential names", () => {
    const { dnKeys, win } = loadDnKeys();
    const names = ["dn_api_key", "dn_api_keys", "sw_claude_key", "sw_openai_key", "sw_gemini_key", "sw_groq_key", "sw_openrouter_key", "sw_key_virustotal"];
    win.__dnUid = "userA";
    names.forEach((n, i) => dnKeys.set(n, "A" + i));
    win.__dnUid = "userB";
    names.forEach((n) => assert.equal(dnKeys.get(n), null, `B cannot read A's ${n}`));
  });

  test("clearForUid wipes only that account's keys", () => {
    const { dnKeys, win } = loadDnKeys();
    win.__dnUid = "userA"; dnKeys.set("dn_api_key", "A");
    win.__dnUid = "userB"; dnKeys.set("dn_api_key", "B");
    win.__dnUid = "userA"; dnKeys.clearForUid();
    assert.equal(dnKeys.get("dn_api_key"), null, "A's key cleared");
    win.__dnUid = "userB";
    assert.equal(dnKeys.get("dn_api_key"), "B", "B's key untouched");
  });

  test("scrubLegacy removes old un-namespaced global credential keys", () => {
    const { dnKeys, win, store } = loadDnKeys();
    // Simulate a browser carrying another account's pre-fix global keys.
    store.set("dn_api_key", "dn_live_OLD");
    store.set("dn_api_keys", JSON.stringify({ anthropic: "sk-ant-OLD" }));
    store.set("sw_claude_key", "sk-ant-OLD");
    dnKeys.scrubLegacy();
    assert.ok(!store.has("dn_api_key"), "legacy dn_api_key removed");
    assert.ok(!store.has("dn_api_keys"), "legacy dn_api_keys removed");
    assert.ok(!store.has("sw_claude_key"), "legacy sw_claude_key removed");
    // After scrub, a signed-in user gets a clean slate, not the old global value.
    win.__dnUid = "userNew";
    assert.equal(dnKeys.get("dn_api_key"), null, "new user does not inherit the scrubbed global key");
  });
});

group("security regression guards (static source checks)", () => {
  const read = (p) => readFileSync(join(pub, p), "utf8");

  test("threat-api.js no longer ships hardcoded VirusTotal/Shodan keys", () => {
    const s = read("js/threat-api.js");
    assert.ok(!/0318a63efb0592db47a2bfbb3a7c16e42a7e1518b997f9ecf844f56c70cf1afd/.test(s), "VirusTotal key literal must be gone");
    assert.ok(!/pwcTag6QwGPVBL0F7H8ky5C3c8HaOAim/.test(s), "Shodan key literal must be gone");
    assert.ok(/var _defaultKeys = \{\};/.test(s), "_defaultKeys is empty");
  });

  test("auth.js no longer returns a shared constant API key", () => {
    const s = read("js/auth.js");
    assert.ok(!/dn_live_0000000000000000000000000000000000000000000000/.test(s), "shared constant fallback key must be gone");
  });

  test("no-account sessions use a random per-session uid, not a fixed shared one", () => {
    const s = read("js/auth.js");
    // The old fixed uids put every Test Mode / app-guest session into one shared
    // dnk:<uid>:* key namespace. They must be generated per session instead.
    assert.ok(!/uid:\s*"test-user"/.test(s), 'fixed "test-user" uid must be gone');
    assert.ok(!/uid:\s*"app-guest"/.test(s), 'fixed "app-guest" uid must be gone');
    assert.ok(!/__dnUid\s*=\s*"app-guest"/.test(s), 'fixed "app-guest" must not be written to __dnUid');
    assert.ok(/_guestUid\("test"\)/.test(s), "Test Mode derives a per-session uid");
    assert.ok(/_guestUid\("app-guest"\)/.test(s), "app guest derives a per-session uid");
  });

  test("credential consumers route through window.dnKeys, not raw global localStorage", () => {
    for (const f of ["js/webai.js", "js/threat-api.js", "js/address-intel.js", "js/labs.js"]) {
      const s = read(f);
      assert.ok(!/localStorage\.getItem\(\s*['"]sw_/.test(s), `${f}: no raw sw_ localStorage read`);
      assert.ok(!/localStorage\.(get|set)Item\(\s*['"]dn_api_keys/.test(s), `${f}: no raw dn_api_keys localStorage access`);
    }
  });

  test("user-keys.js loads before the app module in index.html", () => {
    const html = read("index.html");
    const uk = html.indexOf("/js/user-keys.js");
    const app = html.indexOf('src="/js/auth.js');
    assert.ok(uk > -1, "user-keys.js is referenced");
    assert.ok(uk < app, "user-keys.js loads before auth.js");
  });
});

group("Nexus CLI pairing (refresh-token login replaced)", () => {
  const read = (p) => readFileSync(join(pub, p), "utf8");
  const root = join(here, "..", "..");
  const readRoot = (p) => readFileSync(join(root, p), "utf8");

  test("auth.js no longer exposes the Firebase refresh token as a login code", () => {
    const s = read("js/auth.js");
    // The Nexus panel must not render user.refreshToken into any input value.
    assert.ok(!/value="\$\{esc\(user\.refreshToken/.test(s), "refresh token must not be shown in the Nexus panel");
    assert.ok(!/codeInput\.value\s*=\s*user\.refreshToken/.test(s), "refresh token must not be assigned into the code input");
    // The pairing flow replaces it.
    assert.ok(/_makePairingCode/.test(s), "pairing-code generator present");
    assert.ok(/doc\(db, "pairings", code\)/.test(s), "writes to the pairings collection");
  });

  test("Firestore rules lock down the pairings collection", () => {
    const r = readRoot("firebase/firestore.rules");
    assert.ok(/match \/pairings\/\{code\}/.test(r), "pairings rule block exists");
    assert.ok(/allow read, list, update: if false;/.test(r), "no client read/list/update of pairing codes");
    assert.ok(/request\.resource\.data\.uid == request\.auth\.uid/.test(r), "a user may only create a pairing for their own uid");
  });

  test("functions expose the pair exchange endpoint, backed by the Admin SDK", () => {
    const f = readRoot("functions/index.js");
    assert.ok(/exports\.pair\s*=\s*onRequest/.test(f), "exports.pair endpoint present");
    assert.ok(/admin\.initializeApp\(\)/.test(f), "firebase-admin initialized");
    assert.ok(/collection\("pairings"\)\.doc\(code\)/.test(f), "looks up the code in the pairings collection");
    assert.ok(/ref\.delete\(\)/.test(f), "single-use: the code is deleted on exchange");
    assert.ok(/chatOriginAllowed\(_origin\)/.test(f) && /chatRateLimited\(_ip\)/.test(f), "pair endpoint is origin-gated and rate-limited");
  });
});

group("super-admin via custom claim (hardcoded owner email removed)", () => {
  const read = (p) => readFileSync(join(pub, p), "utf8");
  const root = join(here, "..", "..");
  const readRoot = (p) => readFileSync(join(root, p), "utf8");

  test("no personal owner email is shipped in the client bundle or rules", () => {
    for (const p of ["js/firebase.js", "js/auth.js", "js/admin.js"]) {
      assert.ok(!/cashzombs@gmail\.com/.test(read(p)), `${p} must not hardcode the owner email`);
    }
    assert.ok(!/cashzombs@gmail\.com/.test(readRoot("firebase/firestore.rules")),
      "firestore.rules must not hardcode the owner email");
  });

  test("firebase.js exposes isAdminUser (claim reader), not an OWNER_EMAIL constant", () => {
    const s = read("js/firebase.js");
    assert.ok(!/export const OWNER_EMAIL/.test(s), "OWNER_EMAIL export removed");
    assert.ok(/export async function isAdminUser/.test(s), "isAdminUser helper present");
    assert.ok(/getIdTokenResult\(\)/.test(s), "reads the signed ID token claims");
    assert.ok(/claims\.admin === true/.test(s), "checks the admin custom claim");
  });

  test("Firestore rules gate the owner on the admin token claim and block self-promotion", () => {
    const r = readRoot("firebase/firestore.rules");
    assert.ok(/request\.auth\.token\.admin == true/.test(r), "isOwner() checks the admin claim");
    assert.ok(/affectedKeys\(\)\.hasAny\(\['admin', 'role'(, '[a-z]+')*\]\)/.test(r), "update blocks privilege-field escalation");
    assert.ok(/!request\.resource\.data\.keys\(\)\.hasAny\(\['admin', 'role'(, '[a-z]+')*\]\)/.test(r), "create blocks privilege fields");
    assert.ok(/'tier'/.test(r) && /'entitlements'/.test(r), "tier/entitlements are also non-self-grantable");
  });

  test("auth.js resolves admin from the cached claim flag, not an email compare", () => {
    const s = read("js/auth.js");
    assert.ok(/isAdminUser/.test(s), "imports/uses the claim reader");
    assert.ok(/_isAdmin = await isAdminUser\(user\)/.test(s), "caches the admin flag from the token");
    assert.ok(!/user\.email === OWNER_EMAIL/.test(s), "no email-based owner check remains");
  });

  test("feedback + errors rules bind uid and cap sizes", () => {
    const r = readRoot("firebase/firestore.rules");
    assert.ok(/request\.resource\.data\.message\.size\(\) <= 4001/.test(r), "feedback message is size-capped");
    assert.ok(/hasOnly\(\s*\[?\s*'type','message','email','uid','ts','userAgent','url','resolved'\]?\)/.test(r.replace(/\s+/g, " ")),
      "feedback doc shape is constrained");
  });

  test("set-admin script sets the custom claim via the Admin SDK", () => {
    const s = readRoot("scripts/set-admin.mjs");
    assert.ok(/setCustomUserClaims/.test(s), "sets the custom claim");
    assert.ok(/claims\.admin = true/.test(s), "grants admin:true");
    assert.ok(/--revoke/.test(s), "supports revoke");
  });
});
