// Unit tests for the custom YARA matcher in public/js/malware-classifier.js
import { test, group, assert } from "../harness.mjs";
import { scanCustomYara } from "../../public/js/malware-classifier.js";

const bytesOf = (s) => Uint8Array.from(s, (c) => c.charCodeAt(0));
const pe = bytesOf("MZ\x90\x00This program cannot be run in DOS mode. cmd.exe /c whoami\x00h\x00i\x00");

group("malclass: custom YARA", () => {
  test("text strings with all/any of them", () => {
    const r = scanCustomYara('rule a { strings: $x = "MZ" $y = "This program" condition: all of them }\nrule b { strings: $x = "nope" $y = "cmd.exe" condition: any of them }', pe);
    assert.equal(r.length, 2);
    assert.ok(r[0].matched && r[1].matched);
    assert.equal(r[0].strings[0].first[0], 0);
  });

  test("uint16 magic, at, counts and filesize", () => {
    const r = scanCustomYara('rule m { strings: $mz = "MZ" condition: uint16(0) == 0x5A4D and $mz at 0 and #mz == 1 and filesize < 1KB }', pe);
    assert.ok(r[0].matched, r[0].error || "");
  });

  test("hex wildcards, jumps and alternatives", () => {
    const r = scanCustomYara("rule h { strings: $h = { 4D 5A ?? 00 [1-8] 70 72 ( 6F | 41 ) } condition: $h }", pe);
    assert.ok(r[0].matched, r[0].error || "");
  });

  test("nocase, wide and not", () => {
    const r = scanCustomYara('rule w { strings: $a = "WHOAMI" nocase $b = "hi" wide condition: $a and $b and not $c }', pe);
    assert.ok(r[0].error && /undefined string/.test(r[0].error));
    const ok = scanCustomYara('rule w { strings: $a = "WHOAMI" nocase $b = "hi" wide condition: $a and $b }', pe);
    assert.ok(ok[0].matched, ok[0].error || "");
  });

  test("non-match and unsupported module are reported, not guessed", () => {
    const r = scanCustomYara('rule n { strings: $a = "absent" condition: $a }\nrule p { condition: pe.number_of_sections > 2 }', pe);
    assert.equal(r[0].matched, false);
    assert.equal(r[0].error, null);
    assert.ok(r[1].error);
  });
});
