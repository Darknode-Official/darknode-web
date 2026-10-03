// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the crypto.js mini-tools. See help/README.md for the contract.
// Sample keys and certificates below are throwaway test material for example data only.

const RSA_PUB = "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6ITqdJa56x+rps9HCQ+j\nSfZIG6DihQX1ToW0spKYC34zwDgKfhq7jK2B1qu26BMUPjBrn4aIG2G/4vRLWAQw\nBXmHlxs2qWfs3/le0DGl7wiyf/LFZo+JQAVJeBt9wM32I5Bn92Otj0LBNpMgdIK9\nP0iX2iJ66SCWIhBGuoQfF8Rb4AYjV6ZRYAXUbU4v4TYUWYIoVfaztjJZvovKmAlf\nrYSmUzMShb/tJDNn1brUsElybfn1Hxd16vtDhxZL+h2UymbpNkVcuBhkK375ufPY\n7dTZwtXnxcWEAY9KtPcO4Qeh0KhNdt8/eMERiI/JVN2iEMaEqyREgWLUGOy5giH1\nbwIDAQAB\n-----END PUBLIC KEY-----";
const RSA_PRIV = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDohOp0lrnrH6um\nz0cJD6NJ9kgboOKFBfVOhbSykpgLfjPAOAp+GruMrYHWq7boExQ+MGufhogbYb/i\n9EtYBDAFeYeXGzapZ+zf+V7QMaXvCLJ/8sVmj4lABUl4G33AzfYjkGf3Y62PQsE2\nkyB0gr0/SJfaInrpIJYiEEa6hB8XxFvgBiNXplFgBdRtTi/hNhRZgihV9rO2Mlm+\ni8qYCV+thKZTMxKFv+0kM2fVutSwSXJt+fUfF3Xq+0OHFkv6HZTKZuk2RVy4GGQr\nfvm589jt1NnC1efFxYQBj0q09w7hB6HQqE123z94wRGIj8lU3aIQxoSrJESBYtQY\n7LmCIfVvAgMBAAECggEAH+RjOByYYZyVcarKhn6jmfhyyX9WsoIvtFZ4g2nB+wmT\nVZEaN1O5V8FQpr4kt04un50KlfXg40iUBjAVyXvBjm6t31b3N2MuxUWx8IJuzQt3\nWD9XPgr/+0z+V8AFjpVxZk1fRTphyt2QHMkvUWvBQ1XUpjHGhAVZMlDjMp/+l8av\nD/qonvlx0hs4dOftDucrAsDpKg4I6lxUt6J9Pr6LeJt4U5i7kOO8C0yZhRPXHeaU\np/GlQGU70j7VVfW+keAhzWXz2mV4d4VZLIEO2FVsbjqhFyHczmVGDGtwaoeU/MnB\nKsuR8B6q0v3+XZpHAYo0hxCRAD6SKUL+SPMHgO1YYQKBgQD8UgzqoQ0pF/iq8iMc\nQKz8ue+TieJajmwtho0xAG1veEm8AbR5zXD9HbfBE9kZOCp7J22fbDuuc1BW6n82\n5t4LZ7/f8GykrQY4hDd8xOb9X20ArPMsBUEQo+M5C7625mq8DzvLhsuzRoF3X7rF\nrtlpwX97+joSvAEQOffjck3jfwKBgQDr6PG24wYnPZHjRrLWmdYhkJhAPkaO2yEi\nHAztr09Sr1KGyA1NLN2I/IaB1DZPZdiMomKbaipneo3NSlb9Kdc58Q5EL7zI3+4f\n3gKAXRPI6Ymdg4Dv+cInDNzUhFbqaKK1YdOU4qU4ehtWgRl2BsEmPwNdiUFi5wo7\nmW35WU8mEQKBgQD4otHfkvwo9lov+ZLnkEPmdkLCnCjVG2s2IVSYaNdt9JaUEQoK\nzIr+oX4lYK2Z0GLsIJpBcqIM8czFGSZqr202x/Gndn9YdreekYssA8uq+ZGsDMFD\nK5pGD3klCZHRIZUj488Ea7vm2R9Sxp6Blh7fu7EoNhdrxp81oinHkyd1eQKBgQCF\nZUkYwzK9iaEuxNFna8GbZSnSWeSH7vzDTt04oYLXHHAr6n8q/o2eYjykuRyktNBI\nZaIgg13K+Y+pX7nkmX4sM1R/1gaIB6ecuWrsrrT7TKMWQD/ucmoIrstIGDUVg2lN\n6y066RXH47QFrCZ7iMI7IDKE95HTnRU6Mj3vW0LYIQKBgA0fZ/sZYQ/oM0jBaEt+\nbptmJJ55jGxafj1OGvRK/BixDztXNElB0TnVOhgqe7tiKlB8OKmX0wYPOeFZPjM7\neS1+k60u5KOd9VHPksLBiB1HSN5GMTrazPwxgt5QjH4nGLo2D56zB7hi3SOUqV8D\nQ8QsmEKSN6lo/d9kPv6WIKdn\n-----END PRIVATE KEY-----";
const RSA_SIG = "yEGLfNd7/EdRzjQi5mUF7/AwgxfGwqMBlMubJ1+67UjtpkkFDVxABX+Qmzd8mDmFfHuzY7CCM0jfhnD4P555Bbh+NX0JfFaXofPN4e9tk0AKDyrYs/BEZmMeDSnuyV8YyQZPUyUf8YC3b05iq4xQ7rEH+G7M7yuxy2L9TGEmWARBYwUk14yzxM7uBdtSFEKiBwg7E2DeqPg7ik8vAJHdrtoHCeRB3z+ETbU73F4SWyn/GRqurZadmDZhD9/NLlAMuUjdCCJhljnOKxyQ5QlUB9yK/6LfbNM5fJarGA3UsExZy4h2I7rSYGDf25bdF9o7BNjkfU3BMgKfchIRmvzZ1g==";
const EC_PUB = "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEdgkgXVVEt85n13J9nyNsgZp6q0Iw\nUgtSksI9WSbwCbl+k4ISUCBaRToXl7l7c2dNL5Jh1t2eIOSrn2NVtUiXag==\n-----END PUBLIC KEY-----";
const EC_PRIV = "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/8tPCFcIdaAt/Phr\n7R0wCkNBfWiPNFBPc+S7TTuXR0GhRANCAAR2CSBdVUS3zmfXcn2fI2yBmnqrQjBS\nC1KSwj1ZJvAJuX6TghJQIFpFOheXuXtzZ00vkmHW3Z4g5KufY1W1SJdq\n-----END PRIVATE KEY-----";
const EC_SIG = "+SzqmCKxOGTbv6Vgp49sw8RkDN7azmjeYpksVPb6DtrJxnMK39OYu3KKjNM0rzE3Hkd1YXlZfDL/ZxlFyLdr3g==";
const CERT = "-----BEGIN CERTIFICATE-----\nMIIDsDCCApigAwIBAgIUbuJ+/V1X/2AdWLYD6p5Wr5KR120wDQYJKoZIhvcNAQEL\nBQAwTzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFTATBgNVBAoM\nDEV4YW1wbGUgQ29ycDEUMBIGA1UEAwwLZXhhbXBsZS5jb20wHhcNMjYxMDAzMTky\nMTU5WhcNMjcxMDAzMTkyMTU5WjBPMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2Fs\naWZvcm5pYTEVMBMGA1UECgwMRXhhbXBsZSBDb3JwMRQwEgYDVQQDDAtleGFtcGxl\nLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOiE6nSWuesfq6bP\nRwkPo0n2SBug4oUF9U6FtLKSmAt+M8A4Cn4au4ytgdartugTFD4wa5+GiBthv+L0\nS1gEMAV5h5cbNqln7N/5XtAxpe8Isn/yxWaPiUAFSXgbfcDN9iOQZ/djrY9CwTaT\nIHSCvT9Il9oieukgliIQRrqEHxfEW+AGI1emUWAF1G1OL+E2FFmCKFX2s7YyWb6L\nypgJX62EplMzEoW/7SQzZ9W61LBJcm359R8Xder7Q4cWS/odlMpm6TZFXLgYZCt+\n+bnz2O3U2cLV58XFhAGPSrT3DuEHodCoTXbfP3jBEYiPyVTdohDGhKskRIFi1Bjs\nuYIh9W8CAwEAAaOBgzCBgDAdBgNVHQ4EFgQUfDKVCgN/ZsJq/iTmuvhvggeWuAMw\nHwYDVR0jBBgwFoAUfDKVCgN/ZsJq/iTmuvhvggeWuAMwDwYDVR0TAQH/BAUwAwEB\n/zAtBgNVHREEJjAkggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29thwTAAAIK\nMA0GCSqGSIb3DQEBCwUAA4IBAQDCqeASCrRJ+sY9LK+VWWdradr8tTLVFxOvDza0\n5Mm8kMb6bbp8LvKT4MNqQURtcmxKuAB3G5qoMtY4YAVx99IkbD1inX+ZcugpVWCF\nZ7YrBOrKwcJo4f668Mvy9+lwNw5actiy690TyVagJioERZvcsEpfIS3Bgrenarcc\nXabna/ARArPJGvKXyP8QPpT+0+zsNZErqCjSkaZtw9E/3AbRnYpGPcp2eZHY/7vA\nqigLkNDP/WwtX8yOhRL5JpPhQenAmWgTSA3zx7M1S771v1D/zpFI3Fa4y78J46kc\nkbR9sthCj1REbGjPmUsu7ebTnBT4bvw37/MXpkjOBZnUhHft\n-----END CERTIFICATE-----";
const CSR = "-----BEGIN CERTIFICATE REQUEST-----\nMIICfzCCAWcCAQAwOjELMAkGA1UEBhMCVVMxFTATBgNVBAoMDEV4YW1wbGUgQ29y\ncDEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDohOp0lrnrH6umz0cJD6NJ9kgboOKFBfVOhbSykpgLfjPAOAp+GruM\nrYHWq7boExQ+MGufhogbYb/i9EtYBDAFeYeXGzapZ+zf+V7QMaXvCLJ/8sVmj4lA\nBUl4G33AzfYjkGf3Y62PQsE2kyB0gr0/SJfaInrpIJYiEEa6hB8XxFvgBiNXplFg\nBdRtTi/hNhRZgihV9rO2Mlm+i8qYCV+thKZTMxKFv+0kM2fVutSwSXJt+fUfF3Xq\n+0OHFkv6HZTKZuk2RVy4GGQrfvm589jt1NnC1efFxYQBj0q09w7hB6HQqE123z94\nwRGIj8lU3aIQxoSrJESBYtQY7LmCIfVvAgMBAAGgADANBgkqhkiG9w0BAQsFAAOC\nAQEAGJXoMu9ZHwmNr0UKi+xoB5KAoCTPST3Ww4FVyHLA4adS0UBuNSsLjVmU7hOv\n2QrzVe4yKvufT5Td2xmOwJcCvc7+eaNbj8kVmE6QffucNfGXcA8l56B2wFNiUOqO\nWMkU3vJDuOX5V7Sjs2w2wBtqcuy8P8eHeNMpo1tX6GJc+W76jLRZ0rtsMh0KkO7Y\nknEkupbR4x9c7uWycYBk8R4o1MztUMzmz/d9gHLlEPa79gRHVK6P8uhWY3l9/xbj\nt7GOxzTkGBikjBQBSZKLQTTM7f4c64CVqVOJIJk/wj0WlNTTiwANO2mKqinV9fCL\nioWmzTRFA0pkA6j0c3P8s6yxEQ==\n-----END CERTIFICATE REQUEST-----";
const RSA_PUB_JWK = "{\"kty\":\"RSA\",\"n\":\"6ITqdJa56x-rps9HCQ-jSfZIG6DihQX1ToW0spKYC34zwDgKfhq7jK2B1qu26BMUPjBrn4aIG2G_4vRLWAQwBXmHlxs2qWfs3_le0DGl7wiyf_LFZo-JQAVJeBt9wM32I5Bn92Otj0LBNpMgdIK9P0iX2iJ66SCWIhBGuoQfF8Rb4AYjV6ZRYAXUbU4v4TYUWYIoVfaztjJZvovKmAlfrYSmUzMShb_tJDNn1brUsElybfn1Hxd16vtDhxZL-h2UymbpNkVcuBhkK375ufPY7dTZwtXnxcWEAY9KtPcO4Qeh0KhNdt8_eMERiI_JVN2iEMaEqyREgWLUGOy5giH1bw\",\"e\":\"AQAB\"}";
const KEY32 = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const IV12 = "0102030405060708090a0b0c";
const IV16 = "000102030405060708090a0b0c0d0e0f";

export const HELP = {
  "cr-aes-gcm-encrypt": {
    what: "Encrypts text with AES in GCM mode, which also produces an authentication tag so tampering is detectable. You give a key and a one-time IV (nonce) in hex; you get the ciphertext and tag as hex.",
    when: "You want to protect a short message and be sure nobody altered it. Use a fresh random IV for every message with the same key; never reuse one.",
    example: { key: KEY32, iv: IV12, pt: "Attack at dawn", aad: "" },
  },
  "cr-aes-gcm-decrypt": {
    what: "Decrypts AES-GCM ciphertext (with the 16-byte tag appended) and verifies it was not tampered with. Wrong key, IV, extra data or any edit makes it fail.",
    when: "You have AES-GCM output from the matching encrypt tool and the same key/IV, and want the original text back.",
    example: { key: KEY32, iv: IV12, ct: "449e2eb48fffd0e738820726677d808f9a9e43803156ee5fe91e651f1cbe", aad: "" },
  },
  "cr-aes-cbc-encrypt": {
    what: "Encrypts text with AES in CBC mode (with standard PKCS#7 padding). You give a hex key and a 16-byte hex IV; you get ciphertext hex.",
    when: "You need classic AES-CBC output, for example to match a system that expects it. CBC has no built-in integrity, so add a MAC in real use.",
    example: { key: KEY32, iv: IV16, pt: "Attack at dawn" },
  },
  "cr-aes-cbc-decrypt": {
    what: "Decrypts AES-CBC ciphertext (hex) and removes PKCS#7 padding, giving back the original text.",
    when: "You have AES-CBC ciphertext plus the key and IV and want the plaintext. Fails on a wrong key/IV or corrupted padding.",
    example: { key: KEY32, iv: IV16, ct: "8983f547764229d247a2ac5df1acd54e" },
  },
  "cr-aes-ctr-encrypt": {
    what: "Encrypts text with AES in counter (CTR) mode, turning the cipher into a stream. You give a hex key and a 16-byte initial counter block; you get ciphertext hex. No padding is added.",
    when: "You need stream-style AES, for example to match a protocol using CTR. The counter/nonce must be unique per message under one key.",
    example: { key: KEY32, ctr: IV16, bits: "64", pt: "Attack at dawn" },
  },
  "cr-aes-ctr-decrypt": {
    what: "Decrypts AES-CTR ciphertext (hex). Because CTR is a stream cipher, decryption uses the same counter and key as encryption.",
    when: "You have AES-CTR ciphertext with its key and counter and want the plaintext back.",
    example: { key: KEY32, ctr: IV16, bits: "64", ct: "1b1a70366b9051f7840e315c75ad" },
  },
  "cr-aes-key-gen": {
    what: "Generates a random AES key of the size you choose (128, 192 or 256-bit) and shows it as hex and base64.",
    when: "You need a fresh symmetric key for AES encryption. Keep it secret and store it safely.",
    example: { bits: "256" },
  },
  "cr-pbkdf2": {
    what: "Turns a password and a salt into key bytes using PBKDF2, repeating a hash many times to slow down guessing. Output is the derived key in hex and base64.",
    when: "You need to derive an encryption key from a password, or reproduce a key another system made with PBKDF2. Use a unique salt and a high iteration count.",
    example: { pw: "correct horse battery staple", salt: "3q2-7w==saltvalue", salthex: false, iter: "100000", hash: "SHA-256", len: "256" },
  },
  "cr-hkdf": {
    what: "Expands and mixes existing key material into one or more output keys using HKDF. Input key material and salt are hex; a context string keeps outputs separate.",
    when: "You already have a shared secret (for example from Diffie-Hellman) and need to derive one or more well-separated keys from it.",
    example: { ikm: "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", salt: "000102030405060708090a0b0c", info: "app:session-key", hash: "SHA-256", len: "256" },
  },
  "cr-kdf-advisor": {
    what: "Shows recommended work factors (iterations, memory, cost) for password-hashing algorithms, based on OWASP guidance.",
    when: "You are choosing how to store user passwords and want safe starting parameters for Argon2id, scrypt, bcrypt or PBKDF2.",
    example: { algo: "Argon2id" },
  },
  "cr-rsa-keygen": {
    what: "Creates a brand-new RSA key pair and shows the public key and private key as PEM text, plus the public JWK.",
    when: "You need a fresh RSA key pair for signing or for a certificate request. 2048-bit is the common minimum; larger is stronger but slower.",
    example: { bits: "2048" },
  },
  "cr-ecdsa-keygen": {
    what: "Creates an elliptic-curve key pair (smaller and faster than RSA) and shows public/private PEM and the public JWK.",
    when: "You need an EC key pair for ECDSA signatures or ECDH, for example a P-256 key for JWT ES256.",
    example: { curve: "P-256" },
  },
  "cr-ed25519-keygen": {
    what: "Creates an Ed25519 signing key pair, a modern fast signature scheme, and shows public/private PEM and JWK.",
    when: "You need Ed25519 keys, for example for SSH, signing software, or modern token signing.",
    example: {},
  },
  "cr-x25519-keygen": {
    what: "Creates an X25519 key pair used for key agreement (two parties deriving a shared secret), and shows PEM and JWK.",
    when: "You need Curve25519 keys for ECDH-style key exchange, for example in a messaging or VPN protocol.",
    example: {},
  },
  "cr-rsa-sign": {
    what: "Signs a message with an RSA private key (in PKCS#8 PEM form) and returns the signature in base64 and hex. You can pick PKCS#1 v1.5 or PSS and the hash.",
    when: "You want to prove a message came from you, using an RSA private key you control.",
    example: { pem: RSA_PRIV, msg: "The quick brown fox", scheme: "PKCS1v1.5", hash: "SHA-256" },
  },
  "cr-rsa-verify": {
    what: "Checks an RSA signature (base64) against a message using an RSA public key (SPKI PEM). Tells you VALID or INVALID.",
    when: "You received a signed message and the signer's public key and want to confirm the signature is genuine.",
    example: { pem: RSA_PUB, msg: "The quick brown fox", sig: RSA_SIG, scheme: "PKCS1v1.5", hash: "SHA-256" },
  },
  "cr-ecdsa-sign": {
    what: "Signs a message with an elliptic-curve private key (PKCS#8 PEM) and returns the raw r||s signature in base64/hex.",
    when: "You want a compact EC signature for a message, using an EC private key you control.",
    example: { pem: EC_PRIV, curve: "P-256", msg: "The quick brown fox", hash: "SHA-256" },
  },
  "cr-ecdsa-verify": {
    what: "Checks an ECDSA raw (r||s) signature in base64 against a message using an EC public key (SPKI PEM). Returns VALID or INVALID.",
    when: "You received an EC-signed message and the signer's public key and want to confirm it.",
    example: { pem: EC_PUB, curve: "P-256", msg: "The quick brown fox", sig: EC_SIG, hash: "SHA-256" },
  },
  "cr-jwk-to-pem": {
    what: "Converts a key in JWK (JSON) form into the PEM text format. Public keys become SPKI PEM; private keys (with a 'd' value) become PKCS#8 PEM.",
    when: "A tool gave you a JWK but the next tool needs PEM, for example to feed a key into OpenSSL.",
    example: { jwk: RSA_PUB_JWK },
  },
  "cr-pem-to-jwk": {
    what: "Converts a PEM key (SPKI public or PKCS#8 private) into JWK (JSON) form, detecting whether it is RSA, EC or Ed25519/X25519 automatically.",
    when: "You have a PEM key but a system (like a JWKS endpoint or a JWT library) needs it as a JWK.",
    example: { pem: RSA_PUB },
  },
  "cr-jwk-thumbprint": {
    what: "Computes the standard RFC 7638 fingerprint of a JWK (a SHA-256 over its required fields) as base64url. This value is often used as the key id (kid).",
    when: "You need a stable, canonical identifier for a public key, for example to set its 'kid' in a JWKS.",
    example: { jwk: RSA_PUB_JWK },
  },
  "cr-pem-inspect": {
    what: "Looks at a PEM block, reports its label (CERTIFICATE, PUBLIC KEY, etc.), decodes the base64 body and shows the DER byte length and first bytes.",
    when: "You have a PEM blob and want a quick sanity check of what it is before parsing it fully.",
    example: { pem: RSA_PUB },
  },
  "cr-pem-wrap": {
    what: "Converts between raw DER bytes and PEM text. One direction wraps DER (hex or base64) into a labelled PEM block; the other unwraps a PEM block back to DER hex.",
    when: "You have raw DER and need PEM to paste somewhere, or you have PEM and need the raw DER bytes.",
    example: { mode: "PEM to DER", label: "CERTIFICATE", data: CERT },
  },
  "cr-asn1-decode": {
    what: "Decodes ASN.1 DER data (from hex, base64 or PEM) into an indented tree showing each tag, length and value, naming known object identifiers.",
    when: "You are inspecting the raw structure of a certificate, key or other DER-encoded crypto object.",
    example: { data: EC_PUB },
  },
  "cr-x509-parse": {
    what: "Reads an X.509 certificate (PEM or DER) and prints the important fields: version, serial, issuer, subject, validity dates, public key, subject alternative names and extensions.",
    when: "You have a TLS/website certificate and want to see who it is for, who issued it, when it expires and what it allows.",
    example: { pem: CERT },
  },
  "cr-csr-parse": {
    what: "Reads a certificate signing request (CSR, PKCS#10) and shows the subject, public-key type and size, signature algorithm and any requested SAN names.",
    when: "You generated or received a CSR and want to confirm what it asks a CA to certify before submitting it.",
    example: { pem: CSR },
  },
  "cr-cert-fingerprint": {
    what: "Computes the SHA-256 and SHA-1 fingerprints of a certificate's DER bytes, the colon-separated values browsers and tools display.",
    when: "You want to pin or compare a certificate by its fingerprint, or match the value shown in a browser.",
    example: { pem: CERT },
  },
  "cr-oid-lookup": {
    what: "Looks up a cryptography or X.509 object identifier (OID). Enter a dotted number to get its name, or part of a name to find matching OIDs.",
    when: "You hit an unfamiliar OID while reading a certificate or ASN.1 structure and want to know what it means.",
    example: { q: "2.5.29.17" },
  },
  "cr-key-strength": {
    what: "Estimates the security level in bits for a key size (RSA/DH modulus, ECC curve, symmetric key or hash output) and gives a plain verdict.",
    when: "You are choosing or reviewing a key size and want to know roughly how strong it is by NIST guidance.",
    example: { type: "RSA/DH (modulus bits)", size: "2048" },
  },
  "cr-ec-curve-ref": {
    what: "Shows the key parameters of a common elliptic curve: field size, subgroup order, approximate security level, OID and typical use.",
    when: "You need a quick reference for a curve like P-256, secp256k1 or Curve25519.",
    example: { curve: "P-256 (secp256r1)" },
  },
  "cr-pkcs7-pad": {
    what: "Adds PKCS#7 padding to data so its length becomes a multiple of the cipher block size. Input is text (or hex); output is the padded data in hex.",
    when: "You are learning or debugging block-cipher padding and want to see how PKCS#7 fills the final block.",
    example: { data: "YELLOW SUBMARINE!", hex: false, block: "16" },
  },
  "cr-pkcs7-unpad": {
    what: "Checks whether hex data has valid PKCS#7 padding and, if so, strips it and shows the message. It explains exactly why padding is rejected.",
    when: "You are studying how padding validation works (the basis of padding-oracle attacks) or need to remove PKCS#7 padding.",
    example: { data: "59454c4c4f57205355424d4152494e45210f0f0f0f0f0f0f0f0f0f0f0f0f0f0f", block: "16" },
  },
  "cr-iv-gen": {
    what: "Generates a random initialization vector or nonce of the size you choose, as hex and base64.",
    when: "You need a fresh IV/nonce for an encryption operation. Each message under one key needs its own unique value.",
    example: { size: "12" },
  },
  "cr-const-time-compare": {
    what: "Compares two values for equality in constant time (it always checks every byte) and explains why a normal comparison can leak secrets through timing.",
    when: "You are checking MACs, tokens or password hashes and want to understand and demonstrate timing-safe comparison.",
    example: { a: "5f4dcc3b5aa765d61d8327deb882cf99", b: "5f4dcc3b5aa765d61d8327deb882cf99", hex: true },
  },
  "cr-block-mode-ref": {
    what: "Explains a block-cipher mode (ECB, CBC, CTR, GCM or XTS): what it does, what it needs, and its main security pitfalls.",
    when: "You are choosing an encryption mode or trying to understand one you found in some code or protocol.",
    example: { mode: "GCM" },
  },
  "cr-nonce-reuse-explainer": {
    what: "Explains what goes wrong when a nonce or IV is reused for a given scheme, from leaking plaintext to full key/forgery breaks.",
    when: "You want to understand why 'never reuse a nonce' matters, for CTR, GCM, ChaCha20-Poly1305 or a one-time pad.",
    example: { scheme: "AES-GCM" },
  },
  "cr-padding-oracle-explainer": {
    what: "Explains the CBC padding-oracle attack: how an attacker can decrypt data without the key by watching padding-valid responses, and how to prevent it.",
    when: "You are learning about this classic attack or reviewing a system that reports padding errors.",
    example: {},
  },
  "cr-dh-toy": {
    what: "Runs a small Diffie-Hellman key exchange over integers: from a prime p, generator g and two private values, it computes the public values and the shared secret.",
    when: "You are learning how Diffie-Hellman produces a shared secret. Uses tiny numbers for teaching, not real security.",
    example: { p: "23", g: "5", a: "6", b: "15" },
  },
  "cr-modpow": {
    what: "Computes base raised to an exponent, modulo a number (modular exponentiation), with arbitrarily large integers. This is the core operation of RSA and Diffie-Hellman.",
    when: "You are solving a crypto puzzle or verifying an RSA/DH step and need (base^exp mod m).",
    example: { base: "4", exp: "13", mod: "497" },
  },
  "cr-modinv": {
    what: "Finds the modular inverse of a number: the value x where a*x leaves remainder 1 when divided by m. Reports if no inverse exists.",
    when: "You are computing an RSA private exponent or solving modular equations and need a^-1 mod m.",
    example: { a: "17", m: "3120" },
  },
  "cr-ext-gcd": {
    what: "Runs the extended Euclidean algorithm: it gives the greatest common divisor of two numbers plus the coefficients x and y where a*x + b*y equals that gcd.",
    when: "You need Bezout coefficients or the gcd for a number-theory or crypto problem.",
    example: { a: "240", b: "46" },
  },
  "cr-crt": {
    what: "Solves a set of 'x leaves remainder r when divided by m' equations at once using the Chinese Remainder Theorem, giving the combined answer and modulus.",
    when: "You are combining congruences, for example in RSA CRT or a CTF challenge with several moduli.",
    example: { r: "2, 3, 2", m: "3, 5, 7" },
  },
  "cr-gf256-mul": {
    what: "Multiplies two bytes in the special finite field GF(2^8) that AES uses (with polynomial 0x11B). Inputs and output are single hex bytes.",
    when: "You are studying AES internals (MixColumns) or implementing the field arithmetic and want to check a product.",
    example: { a: "57", b: "83" },
  },
  "cr-mod-sqrt": {
    what: "Finds a square root modulo a prime: a value x where x squared leaves remainder a when divided by p. Reports if no root exists.",
    when: "You need a modular square root, for example decompressing an elliptic-curve point or a Rabin/CTF problem.",
    example: { a: "5", p: "41" },
  },
  "cr-jacobi": {
    what: "Computes the Jacobi symbol (a/n) for an odd n, which equals the Legendre symbol when n is prime. It indicates whether a is a square modulo n.",
    when: "You need to test quadratic-residue status in a number-theory or crypto problem.",
    example: { a: "5", n: "21" },
  },
  "cr-rsa-factor": {
    what: "Tries to factor a small RSA modulus n into its two primes p and q, using trial division and Pollard's rho. Works only for weak/small moduli, as in CTFs.",
    when: "You have a deliberately weak RSA public key in a challenge and need its prime factors to break it.",
    example: { n: "3233" },
  },
  "cr-rsa-compute-d": {
    what: "From the two primes p and q and the public exponent e, computes n, the totient values and the RSA private exponent d.",
    when: "You know an RSA key's primes (for example after factoring) and need the private exponent to decrypt or sign.",
    example: { p: "61", q: "53", e: "17" },
  },
  "cr-rsa-decrypt-pq": {
    what: "Decrypts a textbook RSA ciphertext when you know the primes p and q and the public exponent e. It derives d and recovers the message as a number, hex and text.",
    when: "You factored a weak RSA modulus in a CTF and want to recover the plaintext message from the ciphertext.",
    example: { p: "61", q: "53", e: "17", c: "2790" },
  },
  "cr-rsa-encrypt-toy": {
    what: "Performs textbook (unpadded) RSA encryption: c = m^e mod n. The message can be a number or short text. For learning and CTFs only, not real security.",
    when: "You want to produce or check a raw RSA ciphertext for a challenge or demonstration.",
    example: { n: "3233", e: "17", m: "65", astext: false },
  },
  "cr-rsa-crt-decrypt": {
    what: "Decrypts RSA using the Chinese Remainder Theorem parameters (p, q, dP, dQ, qInv) that are stored inside PKCS#1 private keys, for the ciphertext c.",
    when: "You have the CRT components from an RSA private key and a ciphertext and want the message.",
    example: { p: "61", q: "53", dp: "53", dq: "49", qinv: "38", c: "2790" },
  },
  "cr-ecdsa-nonce-reuse": {
    what: "Recovers the secret nonce k and the ECDSA private key d from two signatures that accidentally used the same nonce (so they share the same r value).",
    when: "You have two ECDSA signatures over different messages with an identical r (the classic nonce-reuse flaw) and want to recover the private key.",
    example: { n: "170141183460469231731687303715884105727", r: "555555555555555555", s1: "129296803198373786986125194416233628825", s2: "101686577650780595248085283444859947162", h1: "11111111111111", h2: "22222222222222" },
  },
  "cr-totient": {
    what: "Factors a (small) number n and computes Euler's totient phi(n), the count of integers up to n that share no factor with it. Shows the factorization too.",
    when: "You need phi(n) for an RSA calculation or a number-theory problem and n is small enough to factor.",
    example: { n: "3233" },
  },
  "cr-primality-test": {
    what: "Tests whether a (possibly very large) number is prime using the Miller-Rabin test, with extra random rounds you choose for confidence.",
    when: "You need to know if a number is prime, for example checking an RSA prime or a DH modulus.",
    example: { n: "170141183460469231731687303715884105727", rounds: "12" },
  },
  "cr-random-prime": {
    what: "Generates a random probable prime of the bit length you pick, using secure randomness and Miller-Rabin testing.",
    when: "You need a random prime, for example to build your own RSA key or for a math experiment.",
    example: { bits: "128" },
  },
  "cr-freq-analysis": {
    what: "Counts how often each letter A-Z appears in the text (ignoring case) and shows counts, percentages and a small bar chart.",
    when: "You are breaking a substitution or Caesar-style cipher and want to compare letter frequencies against English.",
    example: { text: "WKLV LV D VLPSOH VXEVWLWXWLRQ FLSKHU WKDW KLGHV WKH SODLQWHAW" },
  },
  "cr-ioc": {
    what: "Computes the index of coincidence of text, a single number that hints whether a cipher is simple (monoalphabetic) or uses a longer key.",
    when: "You are analyzing a Vigenere-style ciphertext and want a clue about its key length or type.",
    example: { text: "LXFOPVEFRNHRXFOPVEFRNHRLXFOPVEFRNHR" },
  },
  "cr-kasiski": {
    what: "Finds repeated chunks in a Vigenere ciphertext, measures the gaps between them and factors those gaps to suggest likely key lengths.",
    when: "You are attacking a Vigenere cipher and need to estimate the key length from repeated patterns.",
    example: { text: "DYDUXRMHTVDVNQDQNWDYDUXRMHARTJGWNQDYDUXRMHTVDVNQDQNW", len: "3" },
  },
  "cr-vigenere-keylen": {
    what: "Estimates a Vigenere key length by splitting the text into columns for each candidate period and averaging the index of coincidence; periods close to English stand out.",
    when: "You have a Vigenere ciphertext and want a ranked list of likely key lengths before solving the key.",
    example: { text: "LXFOPVEFRNHRLXFOPVEFRNHRLXFOPVEFRNHRLXFOPVEFRNHRLXFOPVEFRNHR" },
  },
  "cr-single-byte-xor": {
    what: "Tries all 256 possible single-byte XOR keys against the ciphertext and ranks the results by how much the decoded text looks like English.",
    when: "You have data that was XORed with one repeating byte (a cryptopals-style challenge) and want to find the key and message.",
    example: { data: "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", fmt: "hex" },
  },
  "cr-xor-keylen": {
    what: "Guesses the likely key sizes of a repeating-key XOR ciphertext by measuring the normalized bit distance between blocks, ranking the best candidates.",
    when: "You are breaking repeating-key (Vigenere-style) XOR and need to find the key length first.",
    example: { data: "HUIFFVgQYUgeF1kZCB5WFQ8RWUILB1ldVB5LBE0GCRgRVhdZVB5HFlwGDxdWVB5XGk4KDRFSVhsdCRYbHgAAHgoZHhoKHRYOBAAAHR0WCwdWFQ8dFQ8RWUILB1ldVAADGBwRCxoHGxwWFQ8RWUILBw==", fmt: "base64", max: "40" },
  },
  "cr-repeating-xor-break": {
    what: "Fully breaks a repeating-key XOR ciphertext: it finds the key length, solves each column with single-byte analysis, then shows the recovered key and plaintext.",
    when: "You have a Vigenere-style XOR ciphertext and want the whole thing decrypted automatically.",
    example: { data: "DgsICg0GHksZEUtLJgESDQNEHhoKDwcYSxoGDgEQ", fmt: "base64", keylen: "3" },
  },
  "cr-hex-xor": {
    what: "XORs two equal-length hex strings together byte by byte and returns the result as hex (the cryptopals 'fixed XOR').",
    when: "You need the XOR of two equal-length buffers, for example comparing a ciphertext with a known value.",
    example: { a: "1c0111001f010100061a024b53535009181c", b: "686974207468652062756c6c277320657965" },
  },
  "cr-hamming-distance": {
    what: "Counts how many bits differ between two equal-length inputs (text or hex). This bit distance is used to guess XOR key lengths.",
    when: "You want the bitwise Hamming distance between two strings, for example in a cryptanalysis workflow.",
    example: { a: "this is a test", b: "wokka wokka!!!", hex: false },
  },
  "cr-chi-squared": {
    what: "Scores how closely a text's letter distribution matches English using a chi-squared statistic; a lower number means more English-like.",
    when: "You are automatically ranking candidate decryptions and want a numeric English-likeness score.",
    example: { text: "The quick brown fox jumps over the lazy dog near the river bank at dawn" },
  },
  "cr-shamir-split": {
    what: "Splits a secret into several shares so that only a chosen minimum number of them can rebuild it (Shamir Secret Sharing). Any fewer shares reveal nothing.",
    when: "You want to share control of a secret (like a master key) so that, say, any 3 of 5 trustees can recover it together.",
    example: { secret: "correct horse", hex: false, n: "5", t: "3" },
  },
  "cr-shamir-combine": {
    what: "Rebuilds a secret from enough Shamir shares (in the xx-hex format the split tool produces). Fewer than the threshold will not work.",
    when: "You have collected the required number of shares and want to reconstruct the original secret.",
    example: { shares: "01-ca24107eb5089ae4369a3d5b9f\n02-790a73b7f458a5dbe0ac14c546\n03-d04111bb24334b1fbe595bedbc", ashex: false },
  },
  "cr-chacha20": {
    what: "Encrypts or decrypts with the ChaCha20 stream cipher (RFC 8439). You give a 32-byte key, 12-byte nonce and a counter; encryption and decryption are the same operation.",
    when: "You want to use or verify ChaCha20, for example to match a protocol or a test vector. Never reuse a nonce with the same key.",
    example: { key: KEY32, nonce: IV12, counter: "1", data: "Attack at dawn", mode: "Encrypt (text -> hex)" },
  },
  "cr-chacha20-block": {
    what: "Produces one 64-byte block of ChaCha20 keystream (RFC 8439) from a key, nonce and counter, as hex. Useful for checking against published test vectors.",
    when: "You are implementing or verifying ChaCha20 and want to compare a raw keystream block.",
    example: { key: KEY32, nonce: IV12, counter: "1" },
  },
};
