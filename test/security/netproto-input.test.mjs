// Network-protocol quick tools reject malformed addresses and numbers instead of
// quietly reading a prefix of them (Number("") is 0, parseInt("65536abc") is 65536).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as NP } from "../../public/js/tools/netproto.js";

const run = (id, v) => NP.find((t) => t.id === id).run(v, H);
const isErr = (r) => !!(r && typeof r === "object" && r.error);

group("netproto quick tools: strict input", () => {
  test("TCP/UDP checksum rejects a truncated IPv4 address", () => {
    assert.ok(isErr(run("np-l4-checksum", { hex: "0035003500080000", src: "1.2.3.", dst: "1.2.3.4", proto: "UDP" })));
    assert.ok(isErr(run("np-l4-checksum", { hex: "0035003500080000", src: "1e2.0.0.1", dst: "1.2.3.4", proto: "UDP" })));
    assert.ok(String(run("np-l4-checksum", { hex: "0035003500080000", src: "1.2.3.0", dst: "1.2.3.4", proto: "UDP" })).includes("UDP checksum"));
  });
  test("multicast MAC mapper rejects a malformed IPv4 address", () => {
    assert.ok(isErr(run("np-multicast-mac", { addr: "239..1.1" })));
    assert.ok(String(run("np-multicast-mac", { addr: "224.0.0.251" })).includes("01:00:5e:00:00:fb"));
  });
  test("ASN converter rejects trailing garbage", () => {
    assert.ok(isErr(run("np-asn-convert", { asn: "65536abc" })));
    assert.ok(isErr(run("np-asn-convert", { asn: "1.0x" })));
    assert.ok(String(run("np-asn-convert", { asn: "65536" })).includes("asdot:   1.0"));
  });
  test("BGP community formatter rejects trailing garbage", () => {
    assert.ok(isErr(run("np-bgp-community", { val: "65001:100x" })));
    assert.ok(String(run("np-bgp-community", { val: "65535:65281" })).includes("NO_EXPORT"));
  });
});
