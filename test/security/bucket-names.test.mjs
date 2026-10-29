// S3 bucket name validator: AWS reserves the amzn-s3-demo- prefix and the .mrap,
// --x-s3 and --table-s3 suffixes, and -an for account regional namespace names.
// The tool passed all of them as valid, so a name that CreateBucket rejects was
// reported as fine.

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/cloud.js";

const run = (v) => TOOLS.find((t) => t.id === "cl-s3-name-validate").run(v, H);

group("cl-s3-name-validate: reserved prefixes and suffixes", () => {
  test("reserved names are invalid", () => {
    for (const n of ["amzn-s3-demo-logs", "logs.mrap", "logs--x-s3", "logs--table-s3", "logs-s3alias", "logs--ol-s3", "logs-an"]) {
      assert.ok(run({ name: n }).startsWith("INVALID"), n);
    }
  });
  test("ordinary and account regional namespace names are valid", () => {
    assert.ok(run({ name: "my-logs" }).startsWith("VALID"));
    assert.ok(run({ name: "human" }).startsWith("VALID"));
    const r = run({ name: "logs-111122223333-us-west-2-an" });
    assert.ok(r.startsWith("VALID") && /regional namespace/.test(r));
  });
});
