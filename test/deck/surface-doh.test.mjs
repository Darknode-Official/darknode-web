// Deck attack-surface DNS: a DoH answer carries the CNAME chain, so "A records" (and the IP the
// owning-network lookup uses) must be filtered to the requested type. deck-surface.js imports
// browser-only paths, so it is loaded with those swapped for a stub.

import { test, group, assert } from "../harness.mjs";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const src = readFileSync(new URL("../../public/js/deck-surface.js", import.meta.url), "utf8")
  .replace(/^import \{ dnFetch, dnFetchJSON \} from "\/js\/net\.js";/m, "const dnFetch = null; const dnFetchJSON = async (u) => globalThis.__doh(u);")
  .replace(/^import \{ fetchSubdomainNames \}.*$/m, "const fetchSubdomainNames = null;");
const f = join(mkdtempSync(join(tmpdir(), "surf-")), "s.mjs"); writeFileSync(f, src);
const m = await import(f);

group("deck surface: DNS over HTTPS", () => {
  test("an alias's CNAME target is not listed as an A record; TXT chunks are joined", async () => {
    globalThis.__doh = (u) => /type=A$/.test(u) ? { Answer: [{ type: 5, data: "apex.example." }, { type: 1, data: "192.0.2.10" }] }
      : /type=TXT$/.test(u) ? { Answer: [{ type: 16, data: '"v=spf1 include:a.example" " -all"' }] } : { Answer: [] };
    const r = await m.dns("www.example.com");
    assert.equal(r.A.join(), "192.0.2.10");
    assert.equal(r.TXT[0], "v=spf1 include:a.example -all");
  });
});
