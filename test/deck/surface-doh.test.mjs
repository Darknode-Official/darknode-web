// Deck attack-surface DNS: a DoH answer carries the CNAME chain, so "A records" (and the IP the
// owning-network lookup uses) must be filtered to the requested type. deck-surface.js imports
// browser-only paths, so it is loaded with those swapped for a stub.

import { test, group, assert } from "../harness.mjs";
import { readFileSync, writeFileSync, mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const src = readFileSync(new URL("../../public/js/deck-surface.js", import.meta.url), "utf8")
  .replace(/^import \{ dnFetch, dnFetchJSON \} from "\/js\/net\.js";/m, "const dnFetch = async (u, o) => globalThis.__fetch(u, o); const dnFetchJSON = async (u) => globalThis.__doh(u);")
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
  test("security.txt: an HTML page served for every path is not one; Contact must start a line", async () => {
    globalThis.__fetch = async () => ({ status: 200, body: "<!doctype html><script>var o={contact: 1}</script>" });
    assert.equal((await m.securityTxt("example.com")).found, false);
    globalThis.__fetch = async () => ({ status: 200, body: "Contact: mailto:test@darknode.ai\r\nExpires: 2030-01-01T00:00:00Z\r\n" });
    const r = await m.securityTxt("example.com");
    assert.equal(r.found, true); assert.equal(r.contact, "mailto:test@darknode.ai");
  });
  test("DMARC policy is read from the p= tag, not from inside sp=", async () => {
    globalThis.__doh = (u) => /_dmarc/.test(u) ? { Answer: [{ type: 16, data: '"v=DMARC1; sp=none; p=reject; rua=mailto:test@darknode.ai"' }] } : { Answer: [] };
    assert.equal((await m.emailAuth("example.com")).dmarc.policy, "reject");
  });
});
