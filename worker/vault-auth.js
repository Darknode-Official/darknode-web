// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// Firebase ID-token verification for the VAULT routes, done the way the Admin SDK does
// it: RS256 signature against Google's published securetoken keys, then the audience,
// issuer, expiry, issued-at and subject claims. No service account is needed.

const JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";
const SKEW = 300; // seconds of clock tolerance on iat / auth_time

let _jwks = null, _jwksExp = 0;

async function googleKeys(fetchImpl = fetch) {
  const now = Date.now();
  if (_jwks && now < _jwksExp) return _jwks;
  const r = await fetchImpl(JWKS_URL);
  if (!r.ok) throw new Error("could not load signing keys (" + r.status + ")");
  const m = /max-age=(\d+)/.exec(r.headers.get("cache-control") || "");
  _jwks = (await r.json()).keys || [];
  _jwksExp = now + (m ? Math.min(+m[1], 86400) : 3600) * 1000;
  return _jwks;
}

const b64uBytes = (s) => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(s + "=".repeat((4 - (s.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
};
const b64uJson = (s) => JSON.parse(new TextDecoder().decode(b64uBytes(s)));

// Resolves to { uid, email } or throws with a reason. `opts.keys` (an array of JWKs)
// and `opts.now` (seconds) let tests supply their own key and clock.
export async function verifyIdToken(token, projectId, opts = {}) {
  if (typeof token !== "string") throw new Error("missing token");
  const parts = token.split(".");
  if (parts.length !== 3) throw new Error("malformed token");
  let header, claims;
  try { header = b64uJson(parts[0]); claims = b64uJson(parts[1]); } catch (_) { throw new Error("malformed token"); }
  if (header.alg !== "RS256" || !header.kid) throw new Error("wrong algorithm");
  const keys = opts.keys || await googleKeys(opts.fetch);
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) throw new Error("unknown signing key");
  const key = await crypto.subtle.importKey("jwk", { kty: jwk.kty, n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uBytes(parts[2]), new TextEncoder().encode(parts[0] + "." + parts[1]));
  if (!ok) throw new Error("bad signature");
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  if (claims.aud !== projectId) throw new Error("wrong audience");
  if (claims.iss !== "https://securetoken.google.com/" + projectId) throw new Error("wrong issuer");
  if (!(claims.exp > now)) throw new Error("token expired");
  if (!(claims.iat <= now + SKEW)) throw new Error("token issued in the future");
  if (claims.auth_time != null && !(claims.auth_time <= now + SKEW)) throw new Error("bad auth_time");
  if (typeof claims.sub !== "string" || !claims.sub || claims.sub.length > 128) throw new Error("bad subject");
  return { uid: claims.sub, email: claims.email || "" };
}
