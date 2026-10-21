// Regression tests for the security.txt (RFC 9116) validator pure core.
import { test, assert, group } from "../harness.mjs";
import { validateSecurityTxt } from "../../public/js/security-txt.js";

group("security.txt validator / prototype safety", () => {
  test("a field named Constructor is flagged as unknown (no fail-open)", () => {
    const doc = [
      "Contact: mailto:a@test.darknode.ai",
      "Expires: 2099-01-01T00:00:00.000Z",
      "Constructor: mailto:x@test.darknode.ai",
    ].join("\n");
    const r = validateSecurityTxt(doc);
    const unknown = r.findings.filter((f) => /Unknown field/.test(f.msg) && /Constructor/.test(f.msg));
    assert.equal(unknown.length, 1, "Constructor must be reported as an unknown extension field");
  });

  test("an Object-member field name does not corrupt duplicate detection", () => {
    const doc = [
      "Contact: mailto:a@test.darknode.ai",
      "Expires: 2099-01-01T00:00:00.000Z",
      "ToString: a",
      "ToString: b",
    ].join("\n");
    const r = validateSecurityTxt(doc);
    // toString is an unknown extension, so it must NOT raise the "Multiple <known field>" error.
    assert.ok(r.findings.every((f) => !/Multiple/i.test(f.msg)), "no spurious Multiple-field error");
  });

  test("a well-formed file still validates clean", () => {
    const doc = [
      "Contact: mailto:security@test.darknode.ai",
      "Expires: 2099-01-01T00:00:00.000Z",
    ].join("\n");
    const r = validateSecurityTxt(doc);
    assert.ok(r.ok, "a minimal valid security.txt passes");
  });
});
