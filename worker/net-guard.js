// Shared SSRF guard for every outbound fetch the worker makes on behalf of a
// request (the /api/fetch reader AND monitor alert delivery in notify.js).
// Cloudflare Workers run on the edge and can't reach a private network, and
// there's no `dns`/`net` module, so the guard is hostname/IP-literal based:
// reject localhost, .local/.internal, and private/reserved IP literals — in
// dotted form AND in the decimal/hex/octal/short encodings that resolve to the
// same address (a classic private-range bypass, e.g. http://2130706433/ ==
// 127.0.0.1, http://0x7f000001/, http://0177.0.0.1/).

// Parse any inet_aton-style numeric IPv4 (1-4 parts, each decimal/0x-hex/0-octal)
// to its canonical dotted form, or null if `host` is not a pure numeric address.
export function normalizeIpv4(host) {
  const parts = host.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  const nums = [];
  for (const part of parts) {
    if (part === "") return null;
    let n;
    if (/^0x[0-9a-f]+$/i.test(part)) n = parseInt(part, 16);
    else if (/^0[0-7]+$/.test(part)) n = parseInt(part, 8);
    else if (/^[1-9][0-9]*$/.test(part) || part === "0") n = parseInt(part, 10);
    else return null;              // a non-numeric label => not a numeric IP
    if (!Number.isFinite(n) || n < 0) return null;
    nums.push(n);
  }
  // inet_aton: the final part fills the remaining low-order bytes.
  const last = nums[nums.length - 1];
  const lastMax = Math.pow(256, 4 - (nums.length - 1));
  if (last >= lastMax) return null;
  for (let i = 0; i < nums.length - 1; i++) if (nums[i] > 255) return null;
  let value = last;
  for (let i = 0; i < nums.length - 1; i++) value += nums[i] * Math.pow(256, 3 - i);
  return [(value >>> 24) & 255, (value >>> 16) & 255, (value >>> 8) & 255, value & 255].join(".");
}

export function ipv4Private(host) {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return false;
  const p = m.slice(1).map(Number);
  if (p.some((n) => n > 255)) return true;
  if (p[0] === 0 || p[0] === 10 || p[0] === 127) return true;
  if (p[0] === 169 && p[1] === 254) return true;          // link-local + cloud metadata
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 100 && p[1] >= 64 && p[1] <= 127) return true; // CGNAT
  if (p[0] >= 224) return true;                            // multicast / reserved
  return false;
}

export function hostAllowed(u) {
  if (u.protocol !== "http:" && u.protocol !== "https:") return false;
  const h = u.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!h || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal") || h.endsWith(".localhost")) return false;
  // Test the canonical dotted form so numeric-encoded private addresses can't slip through.
  const dotted = normalizeIpv4(h) || h;
  if (ipv4Private(dotted)) return false;
  if (h.includes(":")) { // IPv6 literal
    if (h === "::1" || h === "::") return false;
    if (/^fe[89a-f]/.test(h) || h.startsWith("fc") || h.startsWith("fd")) return false;
    if (h.startsWith("::ffff:") && ipv4Private(h.slice(7))) return false;
    // An IPv4 address carried in IPv6 reaches that IPv4 host. URL() rewrites ::ffff:169.254.169.254
    // to ::ffff:a9fe:a9fe, which the dotted check above never saw; also NAT64 (64:ff9b::),
    // the deprecated IPv4-compatible ::a.b.c.d, and 6to4 (2002:AABB:CCDD::).
    const hx = (a, b) => { const x = parseInt(a, 16), y = parseInt(b, 16); return [x >> 8, x & 255, y >> 8, y & 255].join("."); };
    const emb = /^(?:::ffff:|64:ff9b::|::)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(h) || /^2002:([0-9a-f]{1,4}):([0-9a-f]{1,4})(?::|$)/.exec(h);
    if (emb && ipv4Private(hx(emb[1], emb[2]))) return false;
    if (/^(?:64:ff9b::|::)(\d+\.\d+\.\d+\.\d+)$/.test(h) && ipv4Private(h.replace(/^.*:/, ""))) return false;
  }
  return true;
}
