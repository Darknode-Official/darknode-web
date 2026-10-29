// Cron Next Runs. Month and weekday names (JAN, mon-fri) were rejected as
// malformed; N/step (50/5) ran only at N instead of N to the end of the field;
// and a day field like */2 counted as restricted, so "*/2 ... MON" ran on every
// Monday or odd day where Linux cron (Vixie/cronie) runs odd-numbered Mondays.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/devx.js";

const next = (expr, count) => {
  const r = TOOLS.find((t) => t.id === "dv-cron-next").run({ expr, count }, H);
  return typeof r === "string" ? r.split("\n").filter(Boolean).map((l) => new Date(l)) : r;
};

group("dv-cron-next: names, N/step, star day fields", () => {
  test("month and weekday names in any case, also in ranges", () => {
    const r = next("0 9 * JAN-mar mon-FRI", 10);
    assert.ok(Array.isArray(r) && r.length === 10, JSON.stringify(r));
    for (const d of r) assert.ok(d.getMonth() <= 2 && d.getDay() >= 1 && d.getDay() <= 5, String(d));
  });
  test("an unknown name is an error", () => {
    assert.ok(next("0 0 1 * FOO", 1).error);
  });
  test("N/step runs from N to the end of the field", () => {
    const mins = new Set(next("50/5 * * * *", 6).map((d) => d.getMinutes()));
    assert.deepEqual([...mins].sort((a, b) => a - b), [50, 55]);
  });
  test("*/2 in day-of-month is ANDed with a weekday", () => {
    for (const d of next("0 0 */2 * MON", 6)) assert.ok(d.getDay() === 1 && d.getDate() % 2 === 1, String(d));
  });
});

group("dv-cron-explain: steps, invalid fields and the day rule", () => {
  const explain = (expr) => TOOLS.find((t) => t.id === "dv-cron-explain").run({ expr }, H);
  test("N/step and a-b/n are described, not echoed as 'at 50/5'", () => {
    const r = explain("50/5 9-17/2 * * *");
    assert.ok(/every 5 from 50 to 59/.test(r) && /every 2 from 9 to 17/.test(r), r);
  });
  test("an out-of-range field is marked invalid", () => {
    assert.ok(/INVALID: not a valid minute field/.test(explain("61 0 * * *")));
  });
  test("the day-of-month / day-of-week rule is explained", () => {
    assert.ok(/OR the day of week/.test(explain("0 0 13 * FRI")));
    assert.ok(/AND the day of week/.test(explain("0 0 */2 * MON")));
  });
});
