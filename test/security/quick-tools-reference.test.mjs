// Quick tools checked against published reference values (RFCs and specification examples).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS as NET } from "../../public/js/tools/network.js";
import { TOOLS as IDN } from "../../public/js/tools/identity.js";
import { TOOLS as DEV } from "../../public/js/tools/dev.js";
import { TOOLS as DEVX } from "../../public/js/tools/devx.js";
import { TOOLS as NP } from "../../public/js/tools/netproto.js";

const run = (list, id, v) => list.find((t) => t.id === id).run(v, H);
const b32 = (s) => H.base32encode(s).replace(/=+$/, "");

group("quick tools: reference values", () => {
  test("IPv4-mapped IPv6 is printed in RFC 5952 form (no leading zeros)", () => {
    assert.ok(run(NET, "n-ipv4-mapped-ipv6", { ip: "192.0.2.128" }).startsWith("IPv4-mapped: ::ffff:c000:280 "));
    assert.ok(run(NET, "n-ipv4-mapped-ipv6", { ip: "0.0.0.1" }).startsWith("IPv4-mapped: ::ffff:0:1 "));
  });
  test("HOTP matches RFC 4226 Appendix D and TOTP the RFC 6238 SHA-256 vector", async () => {
    const want = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    for (let c = 0; c < 10; c++) assert.ok(String(await run(IDN, "id-hotp", { secret: b32("12345678901234567890"), counter: String(c), digits: "6", algo: "SHA-1" })).includes(want[c]));
    assert.ok(String(await run(IDN, "id-hotp", { secret: b32("12345678901234567890123456789012"), counter: String(Math.floor(1234567890 / 30)), digits: "8", algo: "SHA-256" })).includes("91819424"));
  });
  test("UUID v5 matches the RFC 9562 example", async () => {
    assert.ok(String(await run(DEV, "d-uuid-v5", { namespace: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", name: "www.example.com" })).includes("2ed6657d-e927-568b-95e1-2665a8aea6a2"));
  });
  test("range to CIDR, chmod and the IPv4 header checksum", () => {
    assert.deepEqual(run(NET, "n-range-to-cidr", { start: "192.168.1.5", end: "192.168.1.20" }).match(/\d+\.\d+\.\d+\.\d+\/\d+/g), ["192.168.1.5/32", "192.168.1.6/31", "192.168.1.8/29", "192.168.1.16/30", "192.168.1.20/32"]);
    assert.ok(/\b4755\b/.test(run(DEVX, "dv-chmod-sym-to-oct", { sym: "rwsr-xr-x" })));
    assert.ok(run(DEVX, "dv-chmod-oct-to-sym", { oct: "1776" }).includes("rwxrwxrwT"));
    assert.ok(/b861/i.test(run(NP, "np-ipv4-checksum", { hex: "4500 0073 0000 4000 4011 0000 c0a8 0001 c0a8 00c7", mode: "Compute" })));
  });
});
