// Per-account storage keys (public/js/core/account.js).
import { test, group, assert } from "../harness.mjs";
import { accountScope, acctKey } from "../../public/js/core/account.js";

group("account: per-account storage keys", () => {
  test("scope by uid; guests and Test Mode share one guest scope; none is nouser", () => {
    assert.equal(accountScope("alpha1"), "u_alpha1");
    assert.equal(accountScope("test-0a1b"), "guest");
    assert.equal(accountScope("app-guest-ff"), "guest");
    assert.equal(accountScope(null), "nouser");
  });
  test("acctKey follows the signed-in account at call time", () => {
    const prev = globalThis.__dnUid;
    try {
      globalThis.__dnUid = "alpha1"; const a = acctKey("sw_report");
      globalThis.__dnUid = "beta22"; const b = acctKey("sw_report");
      delete globalThis.__dnUid; const n = acctKey("sw_report");
      assert.equal(a, "sw_report__u_alpha1");
      assert.equal(b, "sw_report__u_beta22");
      assert.equal(n, "sw_report__nouser");
    } finally { if (prev !== undefined) globalThis.__dnUid = prev; }
  });
});
