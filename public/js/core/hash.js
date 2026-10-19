// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Shared non-cryptographic string hashing. Pure: safe in node and the browser.

/**
 * cyrb53 — fast, well-distributed 53-bit string hash (public-domain algorithm),
 * returned base36 so keys stay compact. Not cryptographic; only for bucketing/ids.
 * @param {string} str
 * @param {number} [seed=0]
 * @returns {string} base36 digest
 */
export function cyrb53(str, seed = 0) {
  str = String(str == null ? "" : str);
  let h1 = 0xdeadbeef ^ seed, h2 = 0x41c6ce57 ^ seed;
  for (let i = 0; i < str.length; i++) {
    const ch = str.charCodeAt(i);
    h1 = Math.imul(h1 ^ ch, 2654435761);
    h2 = Math.imul(h2 ^ ch, 1597334677);
  }
  h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
  h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
  const n = 4294967296 * (2097151 & h2) + (h1 >>> 0);
  return n.toString(36);
}
