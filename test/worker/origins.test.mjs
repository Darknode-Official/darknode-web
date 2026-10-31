// The proxy's browser-origin allowlist: our own sites and Firebase preview channels in,
// look-alike hosts out.
import { test, group, assert } from "../harness.mjs";
import { originAllowed } from "../../worker/worker.js";

group("worker: allowed origins", () => {
  test("own sites, Firebase hosts and their preview channels are allowed", () => {
    for (const o of ["https://darknode.ai", "https://sentinel-b4194.web.app", "https://sentinel-b4194-6173e.web.app",
      "https://sentinel-b4194--phase0-build-4zcggyl7.web.app", "https://sentinel-b4194-6173e--pr12-ab12cd34.web.app", ""])
      assert.equal(originAllowed(o), true, o);
  });
  test("look-alikes, other Firebase sites and plain http are refused", () => {
    for (const o of ["https://evil.com", "https://sentinel-b4194.web.app.evil.com", "https://xsentinel-b4194.web.app",
      "https://sentinel-b4194-evil.web.app", "https://other--sentinel-b4194.web.app", "http://sentinel-b4194.web.app"])
      assert.equal(originAllowed(o), false, o);
  });
});
