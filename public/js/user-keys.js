// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Per-user credential storage.
//
// localStorage is shared by every account that signs in on the same browser
// profile. If a credential (an API key, a provider token) is stored under a
// fixed key, a second user who signs in later reads the first user's key and
// believes it is their own. Every credential MUST therefore be namespaced by
// the authenticated Firebase uid, enforced here at the storage layer rather
// than by the UI. No uid => no access (reads return null, writes are dropped).
// This never returns a shared or constant key.
//
// window.__dnUid is maintained by auth.js on every auth-state change. This file
// is a classic script (not a module) so the module app AND the dynamically
// injected classic scripts (threat-api.js) can both use window.dnKeys.
(function () {
  "use strict";
  // Un-namespaced credential keys written by older builds. They may belong to a
  // different account that used this browser, so we cannot attribute them to the
  // current uid — we delete them rather than migrate.
  var LEGACY = [
    "dn_api_key", "dn_api_keys",
    "sw_groq_key", "sw_openrouter_key", "sw_claude_key", "sw_openai_key",
    "sw_gemini_key", "sw_mistral_key",
  ];
  function uid() { try { return window.__dnUid || null; } catch (_) { return null; } }
  function nsName(name) { var u = uid(); return u ? ("dnk:" + u + ":" + name) : null; }

  function get(name) {
    try { var k = nsName(name); return k ? localStorage.getItem(k) : null; } catch (_) { return null; }
  }
  function set(name, val) {
    try {
      var k = nsName(name);
      if (!k) return false; // not signed in -> never persist a credential
      if (val == null || val === "") localStorage.removeItem(k);
      else localStorage.setItem(k, String(val));
      return true;
    } catch (_) { return false; }
  }
  function del(name) { try { var k = nsName(name); if (k) localStorage.removeItem(k); } catch (_) {} }
  function getJSON(name) { try { var v = get(name); return v ? JSON.parse(v) : {}; } catch (_) { return {}; } }
  function setJSON(name, obj) { try { return set(name, JSON.stringify(obj || {})); } catch (_) { return false; } }

  // Remove the legacy un-namespaced credential keys. Idempotent; called once on
  // boot by auth.js. Scrubbing also closes the cross-user window on any browser
  // that still carries a previous account's global keys.
  function scrubLegacy() { try { for (var i = 0; i < LEGACY.length; i++) localStorage.removeItem(LEGACY[i]); } catch (_) {} }

  // Remove every namespaced credential for one uid (used by an explicit "clear"
  // and defensively available for logout).
  function clearForUid(u) {
    try {
      u = u || uid(); if (!u) return;
      var pfx = "dnk:" + u + ":", rm = [], i, k;
      for (i = 0; i < localStorage.length; i++) { k = localStorage.key(i); if (k && k.indexOf(pfx) === 0) rm.push(k); }
      for (i = 0; i < rm.length; i++) localStorage.removeItem(rm[i]);
    } catch (_) {}
  }

  window.dnKeys = {
    get: get, set: set, del: del, getJSON: getJSON, setJSON: setJSON,
    scrubLegacy: scrubLegacy, clearForUid: clearForUid, uid: uid,
  };
})();
