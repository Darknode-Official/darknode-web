// X.509 Certificate Parser: names and SANs printed the way OpenSSL prints them.
// Fixtures made with openssl req -x509 (self-signed, test-only keys, darknode.ai names).

import { test, assert, group } from "../harness.mjs";
import { H } from "../../public/js/tools/_helpers.js";
import { TOOLS } from "../../public/js/tools/crypto.js";

// subject CN=long.darknode.ai, O="A, B" + OU=Unit; SAN IP:2001:db8::1, URI; notAfter 2108 (GeneralizedTime)
const LONG = `-----BEGIN CERTIFICATE-----
MIIDtjCCAp6gAwIBAgIUNSKC5x0vXLquMJ4BWxwWxLWvOxQwDQYJKoZIhvcNAQEL
BQAwNzEZMBcGA1UEAwwQbG9uZy5kYXJrbm9kZS5haTEaMAsGA1UECgwEQSwgQjAL
BgNVBAsMBFVuaXQwIBcNMjYxMDI5MDQzNjA1WhgPMjEwODEyMTgwNDM2MDVaMDcx
GTAXBgNVBAMMEGxvbmcuZGFya25vZGUuYWkxGjALBgNVBAoMBEEsIEIwCwYDVQQL
DARVbml0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsEdxH4oW3AQ5
j5gv10BUz8YmtdNNkDzvDy2GzlEfsXxCdjV31jYQqFJP2HlSeIGoaQUMEClmdWKT
a5us+OYOky04kIhogYOU8HhUtRvNO8DicT9D03pHkc9ZxqO8h5M3QP/QTCGU52iZ
VHJkwxRyI7ZvxyBkM0LCT6KMuGlOdNuz9RKbunhkdq6VFWlUDIhv0aPZDbrl2QXg
sLL1VeKv7Z02TWGzvridTAThOcKOXz/nGHcarppgRV/BhH+i2x54gG/PanFfz0Q2
b/yMXfslVKIvUvOP5mqwaIG7XOiftW7IRZaz3hhTedw4dx9v5Gk2e4QcyjzOrtYb
Mbg4gHCQDQIDAQABo4G3MIG0MB0GA1UdDgQWBBT9bR2d16RIACO4QE11mmuLfbpE
XDAfBgNVHSMEGDAWgBT9bR2d16RIACO4QE11mmuLfbpEXDAPBgNVHRMBAf8EBTAD
AQH/MDIGA1UdEQQrMCmHECABDbgAAAAAAAAAAAAAAAGGFWh0dHBzOi8vZGFya25v
ZGUuYWkveDAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsG
AQUFBwMCMA0GCSqGSIb3DQEBCwUAA4IBAQB7uzXlm/TupJGxOGo1DeRHmv6Z9Kjy
nqx2C5S4FQVcAEj3ScFsFan5egeiX+dU+aXs1y5DtYBtC9TPksnetuqwJay/V/D+
kP/vLoXXSWEklyzOnGZEmj2R53o0c0q7NY1uGvJcU3xAjd+MJ9sXCkcmUjuYVtnm
TjG5dPJpu0EQF/1ySSCCgkq3/3vP/v50/Kdenj7RwpVV56q4bEYjmSCrk0kleNB6
oLXJflkCb3Melvxf1iqVghDT4s6bhsKeBOoOfdCYwREpiUJWJRWkhnYE4Y/OEsBo
nhB9BFE4NS2016NBtyJcHEY8z+C040BFRwsUFMHLQCDSNwfEEFcXbz80
-----END CERTIFICATE-----`;
// subject CN=bmp test, encoded as a BMPString (UTF-16BE)
const BMP = `-----BEGIN CERTIFICATE-----
MIIBMDCB1wIUdECx4uHTg5cIws+OydwLkd0wNdQwCgYIKoZIzj0EAwIwGzEZMBcG
A1UEAx4QAGIAbQBwACAAdABlAHMAdDAeFw0yNjEwMjkwNDM3MTRaFw0yNjExMDMw
NDM3MTRaMBsxGTAXBgNVBAMeEABiAG0AcAAgAHQAZQBzAHQwWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAAQ8Sjo8CsvuG0zZTJTVZR5b1bW5VLXmsGZV+AjFeINefkmz
8xaasvA8M3eok7U8FiO8qqmNUax10Hw+bXjGxagcMAoGCCqGSM49BAMCA0gAMEUC
IBWelh/grGhTpJE3wpR4HaWmXvDc0rWhK+jOqUot7AhIAiEAt2bpAvwvh7BOOxX2
/cngQhI8Yy5HLVvvNjk+vDFuN60=
-----END CERTIFICATE-----`;
const parse = (pem) => TOOLS.find((t) => t.id === "cr-x509-parse").run({ pem }, H);

group("X.509 parser", () => {
  test("an IPv6 subjectAltName prints as an address, not raw hex", async () => {
    assert.ok((await parse(LONG)).includes("IP:2001:db8::1"));
  });
  test("a comma inside a name value is escaped so it reads as one field", async () => {
    assert.ok((await parse(LONG)).includes("O=A\\, B"));
  });
  test("a BMPString name is decoded as UTF-16", async () => {
    assert.ok(/Subject:\s+CN=bmp test$/m.test(await parse(BMP)));
  });
  test("a notAfter past 2050 (GeneralizedTime) is read", async () => {
    assert.ok((await parse(LONG)).includes("Not after:        2108-"));
  });
});
