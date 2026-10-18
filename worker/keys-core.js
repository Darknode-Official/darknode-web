// Workspace API key crypto (Deck D5). PURE (WebCrypto only) — no storage, no network.
// Keys are server-issued and shown once; only their SHA-256 hash is ever stored, so a
// leaked store cannot be used to call the API. This replaces the old client-minted
// sk-darknode-* keys (which authenticated nothing — a fake feature). Works in the
// worker and in node (both expose globalThis.crypto).

export const SCOPES = ["ingest:write", "findings:read"];

const b64url = (bytes) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const randHex = (n) => hex(crypto.getRandomValues(new Uint8Array(n)));

// A fresh key: { key, keyId, prefix }. `key` is the full secret (returned once);
// `keyId` identifies it in storage and logs; `prefix` is the safe display stub.
export function generateKey() {
  const keyId = randHex(5);                                   // 10 hex chars
  const secret = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const key = `dk_${keyId}_${secret}`;
  return { key, keyId, prefix: `dk_${keyId}_` };
}

// SHA-256 hex of the full key string — what we store and compare against.
export async function hashKey(key) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(String(key || "")));
  return hex(buf);
}

// The keyId embedded in a presented key, or "" if malformed.
export function keyIdOf(key) {
  const m = /^dk_([0-9a-f]{10})_[A-Za-z0-9_-]{20,}$/.exec(String(key || ""));
  return m ? m[1] : "";
}

// Display stub for a stored key record (never the secret).
export const keyPrefix = (keyId) => `dk_${keyId}_…`;

// Clean a requested scope list to the known, granted ones.
export function normalizeScopes(scopes) {
  const set = new Set((Array.isArray(scopes) ? scopes : []).map((s) => String(s).trim()));
  const out = SCOPES.filter((s) => set.has(s));
  return out.length ? out : ["ingest:write"];   // a key with no valid scope still ingests
}

export function hasScope(granted, needed) {
  return Array.isArray(granted) && granted.includes(needed);
}

// Constant-time-ish compare of two equal-length hex strings.
export function timingSafeEqual(a, b) {
  a = String(a || ""); b = String(b || "");
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}
