// Slash dates in tool imports: 25/12/2024 can only be day-first (EU-locale Excel exports)
// and must not roll over into 2026; impossible dates are rejected, never shifted.

import { test, assert, group } from "../harness.mjs";
import { parseTs as vulnTs } from "../../public/js/exposure/vulnimport-engine.js";
import * as oauth from "../../public/js/identity/oauthgov-engine.js";
import * as aware from "../../public/js/compliance/awareness-engine.js";
import * as fleet from "../../public/js/exposure/fleetcomply-engine.js";
import * as vpn from "../../public/js/identity/vpnaudit-engine.js";
import * as ct from "../../public/js/ops/cloudtrail-engine.js";
import { parseTs as huntTs } from "../../public/js/ops/log-hunter-engine.js";
import { toTime as nhiTime } from "../../public/js/identity/nhi-engine.js";
import { toDay as evDay } from "../../public/js/compliance/evidence-engine.js";

const fn = (m) => m.parseTs || m.parseTime || m.toEpoch || m.parseDate;
const iso = (v) => (v == null || Number.isNaN(v) ? null : new Date(v instanceof Date ? v.getTime() : v).toISOString().slice(0, 16));
const engines = { vulnimport: vulnTs, oauthgov: fn(oauth), awareness: fn(aware), fleetcomply: fn(fleet), vpnaudit: fn(vpn), cloudtrail: fn(ct), loghunter: huntTs, nhi: nhiTime };

group("day-first slash dates", () => {
  for (const [name, parse] of Object.entries(engines)) {
    test(name + ": 25/12 and 13/01 read day-first, 02/01 stays month-first, 13/13 rejected", () => {
      assert.equal(iso(parse("25/12/2024 1:00:00")), "2024-12-25T01:00");
      assert.equal(iso(parse("13/01/2024 10:00:00")), "2024-01-13T10:00");
      assert.equal(iso(parse("02/01/2024 3:00:00")), "2024-02-01T03:00");
      assert.equal(iso(parse("13/13/2024 1:00:00")), null);
    });
  }
  test("vulnimport: out-of-range ISO dates are rejected, not rolled over", () => {
    assert.equal(vulnTs("2024-13-45"), null);
    assert.equal(vulnTs("2023-02-29"), null);
    assert.equal(iso(vulnTs("2024-02-29")), "2024-02-29T00:00");
  });
  test("evidence day: 25/12/2024 is 2024-12-25, 13/13 rejected", () => {
    assert.equal(evDay("25/12/2024"), "2024-12-25");
    assert.equal(evDay("02/01/2024"), "2024-02-01");
    assert.equal(evDay("13/13/2024"), null);
  });
  test("vpnaudit roster day: 25/12/2024 is Dec 25", () => {
    assert.equal(JSON.stringify(vpn.parseDay("25/12/2024")), JSON.stringify({ y: 2024, mo: 12, d: 25 }));
  });
});
