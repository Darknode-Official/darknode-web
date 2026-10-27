// Certificate lookups (Domain check, Certificate watch / fleet, Vendor risk, Domain guard)
// must use a certificate that actually names the host. ct-fetch.js imports a browser-only
// path, so the pure helper is lifted from source.

import { test, group, assert } from "../harness.mjs";
import { readFileSync } from "node:fs";

const src = readFileSync(new URL("../../public/js/dataprotect/ct-fetch.js", import.meta.url), "utf8");
const start = src.indexOf("export function certCovers");
const body = src.slice(start, src.indexOf("\n}\n", start) + 3).replace(/^export /, "");
const certCovers = new Function(body + "; return certCovers;")();

group("ct-fetch: certificate covers the host", () => {
  test("exact names and one-label wildcards cover; siblings and deeper names do not", () => {
    assert.ok(certCovers("github.com\nwww.github.com", "github.com"));
    assert.ok(certCovers("*.github.com\ngithub.com", "docs.github.com"));
    assert.ok(certCovers("*.github.com", "Docs.GitHub.com."));
    assert.notOk(certCovers("*.registry.github.com\nregistry.github.com", "github.com"));
    assert.notOk(certCovers("*.github.com", "github.com"));
    assert.notOk(certCovers("*.github.com", "a.b.github.com"));
    assert.notOk(certCovers("", "github.com"));
  });
  test("lookups filter to covering certificates and try the parent wildcard", () => {
    assert.ok(/const cover = \(rows\) => rows\.filter\(\(r\) => certCovers\(/.test(src));
    assert.ok(/for \(const q of wild \? \[host, wild\] : \[host\]\)/.test(src));
  });
});
