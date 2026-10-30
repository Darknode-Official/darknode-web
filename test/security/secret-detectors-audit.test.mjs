// Audit regressions for the shared secret-detector catalogue (core/secret-detectors.js)
// and the Deck Secret Scan snippet masking. Fake tokens are built by concatenation so
// push protection and the self-scan never see a literal credential.

import { test, assert, group } from "../harness.mjs";
import { detector, findAll, maskSecrets } from "../../public/js/core/secret-detectors.js";
import { scanFile, mask } from "../../public/js/codescan/rules.js";

const ALNUM = "Ab3Xy9Qw2Er5Ty8Ui1Op4As7Df0Gh6Jk3LzMn7Pq2Rs5Tu8Vw1Xy4Za7Bc0De3Fg6Hi9";
const timed = (fn) => { const t = performance.now(); const r = fn(); return [r, performance.now() - t]; };

group("secret-detectors audit: regex cost on adversarial input", () => {

test("pat-assignment is linear on a long credential-word run (was cubic: minutes per 50 KB)", () => {
  const d = detector("pat-assignment");
  const [hits, ms] = timed(() => findAll(d, "password_".repeat(6000)));
  assert.equal(hits.length, 0);
  assert.ok(ms < 1500, "took " + ms.toFixed(0) + " ms");
  const h = findAll(d, 'cfg.db_password = "' + "Xk9vR2" + "pQ7mZ4" + '";');
  assert.equal(h.length, 1);
  assert.equal(h[0].m[1], "cfg.db_password");
  assert.equal(h[0].value, "Xk9vR2" + "pQ7mZ4");
});

test("config-assignment is linear on a long key line", () => {
  const d = detector("config-assignment");
  const [hits, ms] = timed(() => findAll(d, "token".repeat(40000)));
  assert.equal(hits.length, 0);
  assert.ok(ms < 1500, "took " + ms.toFixed(0) + " ms");
  assert.equal(findAll(d, "export DB_PASSWORD=" + "Hq7zP3" + "vN9x!")[0].m[1], "DB_PASSWORD");
});

test("discord-bot-token bounds its first segment (was ~30 s on 200 KB of 'M-')", () => {
  const d = detector("discord-bot-token");
  const [hits, ms] = timed(() => findAll(d, "M-".repeat(100000)));
  assert.equal(hits.length, 0);
  assert.ok(ms < 1500, "took " + ms.toFixed(0) + " ms");
  assert.equal(findAll(d, "MTk4" + ALNUM.slice(0, 22) + "." + "GxYz12" + "." + ALNUM.slice(5, 35)).length, 1);
});

test("jwt bounds its header segment (was ~13 s on 200 KB of 'eyJ-')", () => {
  const d = detector("jwt");
  const [hits, ms] = timed(() => findAll(d, "eyJ-".repeat(50000)));
  assert.equal(hits.length, 0);
  assert.ok(ms < 3000, "took " + ms.toFixed(0) + " ms");
  assert.equal(findAll(d, "eyJhbGciOiJIUzI1NiJ9" + "." + "eyJzdWIiOiI0MiJ9" + "." + ALNUM.slice(0, 43)).length, 1);
});

test("azure-sas bounds its query scan (was ~0.9 s on 200 KB of sv= params)", () => {
  const d = detector("azure-sas");
  const [hits, ms] = timed(() => findAll(d, "?sv=2020-01-01&".repeat(13000)));
  assert.equal(hits.length, 0);
  assert.ok(ms < 500, "took " + ms.toFixed(0) + " ms");
  assert.equal(findAll(d, "https://a.blob.core.windows.net/c?sv=2022-11-02&ss=b&srt=o&sp=r&se=2030-01-01&sig=" + "Ab3Xy9Qw2Er5%2BTy8").length, 1);
});
});

group("secret-detectors audit: Secret Scan snippet masking", () => {

test("maskSecrets hides the repeat and the second token that scanFile leaves in the snippet", () => {
  const g1 = "ghp_" + ALNUM.slice(0, 36), g2 = "ghp_" + ALNUM.slice(10, 46);
  const [same] = scanFile("a.js", 'const a = "' + g1 + '"; // ' + g1);
  const [two] = scanFile("a.js", 'const a = ["' + g1 + '", "' + g2 + '"];');
  assert.ok(same.snippet.includes(g1), "precondition: scanFile leaves the repeat unmasked");
  assert.ok(two.snippet.includes(g2), "precondition: scanFile leaves the second token unmasked");
  for (const s of [maskSecrets(same.snippet, mask), maskSecrets(two.snippet, mask)]) {
    assert.ok(!s.includes(g1) && !s.includes(g2), s);
  }
  assert.equal(maskSecrets("const id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';", mask), "const id = 'f47ac10b-58cc-4372-a567-0e02b2c3d479';");
});
});
