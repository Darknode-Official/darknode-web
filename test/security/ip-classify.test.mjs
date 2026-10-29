// IP classifiers. 255.255.255.255 came out as "Reserved for future use" because
// the 240/4 entry was checked before the limited-broadcast /32 inside it; the
// IPv6 classifier called NAT64 (64:ff9b::/96), discard-only (100::/64) and the
// 3fff::/20 documentation block "Other" or "Global unicast".

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as NET } from "../../public/js/tools/network.js";
import { TOOLS as NP } from "../../public/js/tools/netproto.js";

const run = (id, v) => [...NET, ...NP].find((t) => t.id === id).run(v, H);
const type = (a) => String(run("np-ipv6-classify", { addr: a })).split("Type: ")[1];

group("IP classifiers", () => {
  test("IPv4 limited broadcast", () => {
    assert.equal(run("n-ip-type", { ip: "255.255.255.255" }), "Limited broadcast");
    assert.equal(run("n-ip-type", { ip: "240.0.0.1" }), "Reserved for future use");
  });
  test("IPv6 special-use blocks", () => {
    assert.equal(type("64:ff9b::1.2.3.4"), "NAT64 well-known prefix (64:ff9b::/96, RFC 6052) -> 1.2.3.4");
    assert.equal(type("64:ff9b:1::5"), "NAT64 local-use (64:ff9b:1::/48, RFC 8215)");
    assert.equal(type("100::1"), "Discard-only (100::/64, RFC 6666)");
    assert.equal(type("3fff:fff::1"), "Documentation (3fff::/20, RFC 9637)");
    assert.equal(type("3fff:1000::1"), "Global unicast (2000::/3)");
    assert.equal(type("2002:c000:204::1"), "6to4 (2002::/16) -> 192.0.2.4");
    assert.ok(/scope=3 \(realm-local\)/.test(type("ff03::1")));
  });
});
