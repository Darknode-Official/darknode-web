// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Identity & Access mini-tools: authentication, tokens and identity formats.
// Decoders, builders, calculators and accurate reference tables for OAuth/OIDC,
// JWT/JOSE, OTP (HOTP/TOTP), SAML, Kerberos, LDAP/Active Directory, Windows
// SIDs/RIDs, WebAuthn/FIDO2, SSH keys and credential-storage formats.
// Pure client-side, deterministic. For authorized use. See _schema.md.

const S = (v) => (v == null ? "" : String(v));

// ---- small shared helpers ----
function table(rows) {
  if (!rows.length) return "";
  const w = [];
  rows.forEach((r) => r.forEach((c, i) => { w[i] = Math.max(w[i] || 0, S(c).length); }));
  return rows.map((r) => r.map((c, i) => (i === r.length - 1 ? S(c) : S(c).padEnd(w[i]))).join("   ")).join("\n");
}
function refView(header, rows, q) {
  const needle = S(q).trim().toLowerCase();
  let r = rows;
  if (needle) r = rows.filter((row) => row.some((c) => S(c).toLowerCase().includes(needle)));
  if (!r.length) return `No match for "${q}".`;
  return table([header, header.map((h) => "-".repeat(S(h).length)), ...r]);
}
function b64bytes(s) {
  let t = S(s).trim().replace(/\s+/g, "");
  if (/[-_]/.test(t) && !/[+/]/.test(t)) t = t.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t);
  const u = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i);
  return u;
}
function bytesToB64url(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b32decode(s) {
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const t = S(s).toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0, val = 0; const out = [];
  for (const c of t) { const i = A.indexOf(c); if (i < 0) return null; val = (val << 5) | i; bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
function u64be(n) {
  const b = new Uint8Array(8); let x = BigInt(n);
  for (let i = 7; i >= 0; i--) { b[i] = Number(x & 0xffn); x >>= 8n; }
  return b;
}
async function hmacBytes(hash, keyBytes, msgBytes) {
  const k = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", k, msgBytes);
  return new Uint8Array(sig);
}
function bitLen(bytes) {
  let i = 0; while (i < bytes.length && bytes[i] === 0) i++;
  if (i === bytes.length) return 0;
  let top = bytes[i], b = 0; while (top) { b++; top >>= 1; }
  return (bytes.length - i - 1) * 8 + b;
}
function humanDuration(sec) {
  if (!isFinite(sec)) return "effectively forever";
  if (sec < 1) return "under a second";
  const units = [["year", 31557600], ["day", 86400], ["hour", 3600], ["minute", 60], ["second", 1]];
  for (const [n, s] of units) { if (sec >= s) { const v = sec / s; return `${v >= 1e6 ? v.toExponential(2) : v.toFixed(v < 10 ? 1 : 0)} ${n}${v >= 2 ? "s" : ""}`; } }
  return "under a second";
}
// RFC 1951 raw DEFLATE inflate (for SAML HTTP-Redirect binding). Pure JS.
function inflateRaw(input) {
  const out = []; let pos = 0, bitBuf = 0, bitCnt = 0;
  const getBit = () => { if (bitCnt === 0) { bitBuf = input[pos++]; bitCnt = 8; } const b = bitBuf & 1; bitBuf >>= 1; bitCnt--; return b; };
  const getBits = (n) => { let v = 0; for (let i = 0; i < n; i++) v |= getBit() << i; return v; };
  function build(lengths) {
    const MB = 15, blc = new Array(MB + 1).fill(0);
    for (const l of lengths) if (l) blc[l]++;
    const next = new Array(MB + 1).fill(0); let code = 0;
    for (let b = 1; b <= MB; b++) { code = (code + blc[b - 1]) << 1; next[b] = code; }
    const codes = new Array(lengths.length).fill(-1);
    for (let i = 0; i < lengths.length; i++) if (lengths[i]) codes[i] = next[lengths[i]]++;
    return { lengths, codes };
  }
  function decode(t) {
    let code = 0, len = 0;
    for (;;) {
      code = (code << 1) | getBit(); len++;
      for (let i = 0; i < t.lengths.length; i++) if (t.lengths[i] === len && t.codes[i] === code) return i;
      if (len > 15) throw new Error("bad code");
    }
  }
  const lb = [3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258];
  const le = [0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0];
  const db = [1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577];
  const de = [0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13];
  let bfinal;
  do {
    bfinal = getBit(); const btype = getBits(2);
    if (btype === 0) {
      bitBuf = 0; bitCnt = 0;
      const len = input[pos] | (input[pos + 1] << 8); pos += 4;
      for (let i = 0; i < len; i++) out.push(input[pos++]);
    } else {
      let lit, dist;
      if (btype === 1) {
        const ll = new Array(288);
        for (let i = 0; i <= 143; i++) ll[i] = 8;
        for (let i = 144; i <= 255; i++) ll[i] = 9;
        for (let i = 256; i <= 279; i++) ll[i] = 7;
        for (let i = 280; i <= 287; i++) ll[i] = 8;
        lit = build(ll); dist = build(new Array(30).fill(5));
      } else if (btype === 2) {
        const hlit = getBits(5) + 257, hdist = getBits(5) + 1, hclen = getBits(4) + 4;
        const order = [16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15];
        const cl = new Array(19).fill(0);
        for (let i = 0; i < hclen; i++) cl[order[i]] = getBits(3);
        const ct = build(cl); const lens = [];
        while (lens.length < hlit + hdist) {
          const s = decode(ct);
          if (s < 16) lens.push(s);
          else if (s === 16) { const r = getBits(2) + 3, p = lens[lens.length - 1]; for (let i = 0; i < r; i++) lens.push(p); }
          else if (s === 17) { const r = getBits(3) + 3; for (let i = 0; i < r; i++) lens.push(0); }
          else { const r = getBits(7) + 11; for (let i = 0; i < r; i++) lens.push(0); }
        }
        lit = build(lens.slice(0, hlit)); dist = build(lens.slice(hlit));
      } else throw new Error("bad block type");
      for (;;) {
        const s = decode(lit);
        if (s === 256) break;
        if (s < 256) out.push(s);
        else { const li = s - 257; const length = lb[li] + getBits(le[li]); const ds = decode(dist); const d = db[ds] + getBits(de[ds]); const start = out.length - d; for (let i = 0; i < length; i++) out.push(out[start + i]); }
      }
    }
  } while (!bfinal);
  return new Uint8Array(out);
}
function prettyXml(xml) {
  try {
    const x = S(xml).replace(/\r?\n/g, "").replace(/>\s+</g, "><").replace(/(>)(<)(\/*)/g, "$1\n$2$3");
    let pad = 0; const res = [];
    x.split("\n").forEach((node) => {
      node = node.trim(); if (!node) return;
      if (/^<\//.test(node)) pad = Math.max(0, pad - 1);
      res.push("  ".repeat(pad) + node);
      if (/^<[^!?/][^>]*>$/.test(node) && !/\/>$/.test(node) && !/<\/[^>]+>$/.test(node)) pad++;
    });
    return res.join("\n");
  } catch (e) { return S(xml); }
}
// split on separators, honouring backslash escapes (RFC 4514 style)
function splitEsc(str, seps) {
  const parts = []; let cur = "", esc = false;
  for (const c of str) { if (esc) { cur += c; esc = false; } else if (c === "\\") { cur += c; esc = true; } else if (seps.includes(c)) { parts.push(cur); cur = ""; } else cur += c; }
  parts.push(cur); return parts;
}
function splitPairEsc(s) {
  let esc = false;
  for (let i = 0; i < s.length; i++) { const c = s[i]; if (esc) { esc = false; continue; } if (c === "\\") { esc = true; continue; } if (c === "=") return [s.slice(0, i), s.slice(i + 1)]; }
  return [s, null];
}

// ================= TOOLS =================
export const TOOLS = [
  // ---------------- OAuth 2.0 / OIDC ----------------
  { id: "id-pkce", name: "PKCE Verifier & Challenge (S256)", cat: "identity", desc: "Generate or convert an OAuth 2.0 PKCE code_verifier and derive its code_challenge (RFC 7636).", tags: ["oauth", "pkce", "s256", "code challenge"], button: "Generate", live: false,
    inputs: [
      { k: "verifier", label: "code_verifier (blank = random)", type: "text", placeholder: "leave blank to generate" },
      { k: "method", label: "Challenge method", type: "select", opts: ["S256", "plain"], value: "S256" },
    ],
    async run(v, H) {
      let ver = S(v.verifier).trim();
      if (!ver) ver = bytesToB64url(H.randBytes(32)); // 43-char unreserved verifier
      if (ver.length < 43 || ver.length > 128) return { error: "code_verifier must be 43-128 characters (RFC 7636)." };
      if (!/^[A-Za-z0-9._~-]+$/.test(ver)) return { error: "code_verifier may only use A-Z a-z 0-9 - . _ ~" };
      if (v.method === "plain") return `code_verifier:  ${ver}\ncode_challenge: ${ver}\nmethod:         plain  (S256 is strongly preferred)`;
      const hex = await H.sha256(ver);
      const challenge = bytesToB64url(H.fromHex(hex));
      return `code_verifier:  ${ver}\n   length:      ${ver.length}\ncode_challenge: ${challenge}\nmethod:         S256   (BASE64URL(SHA-256(verifier)))`;
    } },

  { id: "id-oauth-authz-url", name: "OAuth 2.0 Authorization URL Builder", cat: "identity", desc: "Assemble an OAuth 2.0 / OIDC authorization request URL from endpoint, client_id, scopes, PKCE and other parameters.", tags: ["oauth", "oidc", "authorize", "url"], button: "Build",
    inputs: [
      { k: "endpoint", label: "Authorization endpoint", type: "text", placeholder: "https://issuer.example.com/authorize" },
      { k: "client_id", label: "client_id", type: "text", placeholder: "s6BhdRkqt3" },
      { k: "redirect_uri", label: "redirect_uri", type: "text", placeholder: "https://app.example.com/callback" },
      { k: "response_type", label: "response_type", type: "select", opts: ["code", "token", "id_token", "code id_token", "id_token token", "code token", "code id_token token"], value: "code" },
      { k: "scope", label: "scope", type: "text", value: "openid profile email" },
      { k: "state", label: "state", type: "text", placeholder: "xyz123" },
      { k: "code_challenge", label: "code_challenge (PKCE)", type: "text", placeholder: "optional" },
      { k: "ccm", label: "code_challenge_method", type: "select", opts: ["(none)", "S256", "plain"], value: "(none)" },
      { k: "extra", label: "Extra params (key=value per line)", type: "textarea", rows: 2, placeholder: "nonce=n-0S6\nprompt=login" },
    ],
    run(v) {
      const ep = S(v.endpoint).trim();
      if (!ep) return "";
      if (!S(v.client_id).trim()) return { error: "client_id is required." };
      const p = [];
      p.push(["response_type", v.response_type]);
      p.push(["client_id", v.client_id]);
      if (S(v.redirect_uri).trim()) p.push(["redirect_uri", v.redirect_uri]);
      if (S(v.scope).trim()) p.push(["scope", v.scope]);
      if (S(v.state).trim()) p.push(["state", v.state]);
      if (S(v.code_challenge).trim()) { p.push(["code_challenge", v.code_challenge]); p.push(["code_challenge_method", v.ccm === "(none)" ? "S256" : v.ccm]); }
      S(v.extra).split(/\r?\n/).forEach((l) => { const m = l.match(/^([^=]+)=(.*)$/); if (m) p.push([m[1].trim(), m[2].trim()]); });
      const qs = p.map(([k, val]) => `${encodeURIComponent(k)}=${encodeURIComponent(val)}`).join("&");
      const url = ep + (ep.includes("?") ? "&" : "?") + qs;
      return url + "\n\n--- parameters ---\n" + table(p);
    } },

  { id: "id-oauth-grants", name: "OAuth 2.0 Grant Type Reference", cat: "identity", desc: "Look up OAuth 2.0 grant_type values and when each flow is appropriate.", tags: ["oauth", "grant", "flow", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "device, refresh, ..." }],
    run(v) {
      const rows = [
        ["authorization_code", "Authorization Code", "Web/native apps with a redirect; pair with PKCE."],
        ["authorization_code + PKCE", "Auth Code + PKCE", "Public clients (SPA, mobile); no client secret."],
        ["client_credentials", "Client Credentials", "Machine-to-machine; no end user involved."],
        ["refresh_token", "Refresh Token", "Exchange a refresh_token for a new access token."],
        ["password", "Resource Owner Password", "Legacy ROPC; discouraged, avoid for new apps."],
        ["implicit", "Implicit", "Deprecated; tokens returned in URL fragment."],
        ["urn:...:device_code", "Device Authorization", "Input-constrained devices (TVs, CLI); RFC 8628."],
        ["urn:...:jwt-bearer", "JWT Bearer", "Trade a signed JWT assertion for a token; RFC 7523."],
        ["urn:...:saml2-bearer", "SAML 2.0 Bearer", "Trade a SAML assertion for a token; RFC 7522."],
        ["urn:...:token-exchange", "Token Exchange", "Delegation/impersonation token swap; RFC 8693."],
      ];
      return refView(["grant_type", "Name", "When to use"], rows, v.q);
    } },

  { id: "id-oauth-response-types", name: "OAuth 2.0 response_type Reference", cat: "identity", desc: "Explain OAuth 2.0 / OIDC response_type values and the flow each selects.", tags: ["oauth", "oidc", "response_type", "hybrid"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "code, token, id_token" }],
    run(v) {
      const rows = [
        ["code", "Authorization Code flow; most secure, use with PKCE."],
        ["token", "Implicit flow; access token in fragment (deprecated)."],
        ["id_token", "OIDC; ID token only returned from the authorize endpoint."],
        ["id_token token", "OIDC Implicit; ID token + access token in fragment."],
        ["code id_token", "OIDC Hybrid; code plus an ID token up front."],
        ["code token", "OIDC Hybrid; code plus an access token up front."],
        ["code id_token token", "OIDC Hybrid; code + ID token + access token."],
        ["none", "No tokens returned (OIDC); used for logout/session checks."],
      ];
      return refView(["response_type", "Meaning"], rows, v.q);
    } },

  { id: "id-oauth-errors", name: "OAuth 2.0 Error Code Reference", cat: "identity", desc: "Look up OAuth 2.0 / Bearer / device-flow error codes and their meaning.", tags: ["oauth", "error", "invalid_grant", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "invalid_grant" }],
    run(v) {
      const rows = [
        ["invalid_request", "6749", "Request is missing a parameter or is malformed."],
        ["invalid_client", "6749", "Client authentication failed (bad id/secret)."],
        ["invalid_grant", "6749", "Auth code/refresh token invalid, expired or revoked."],
        ["unauthorized_client", "6749", "Client not allowed to use this grant type."],
        ["unsupported_grant_type", "6749", "Grant type not supported by the token endpoint."],
        ["invalid_scope", "6749", "Requested scope is invalid or exceeds what is granted."],
        ["access_denied", "6749", "Resource owner or server denied the request."],
        ["unsupported_response_type", "6749", "Authorization server rejects the response_type."],
        ["server_error", "6749", "Unexpected server error (HTTP 500 equivalent)."],
        ["temporarily_unavailable", "6749", "Server overloaded or in maintenance."],
        ["invalid_token", "6750", "Bearer access token expired, revoked or malformed."],
        ["insufficient_scope", "6750", "Token lacks the scope the resource requires."],
        ["authorization_pending", "8628", "Device flow: user has not yet approved; keep polling."],
        ["slow_down", "8628", "Device flow: increase the polling interval by 5s."],
        ["expired_token", "8628", "Device flow: device_code expired; restart the flow."],
      ];
      return refView(["error", "RFC", "Meaning"], rows, v.q);
    } },

  { id: "id-oauth-device", name: "OAuth 2.0 Device Flow Reference", cat: "identity", desc: "Fields and steps of the OAuth 2.0 Device Authorization Grant (RFC 8628) for input-constrained devices.", tags: ["oauth", "device", "rfc8628", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "user_code, interval" }],
    run(v) {
      const rows = [
        ["device_authorization_endpoint", "Where the device requests codes (returns the fields below)."],
        ["device_code", "Opaque code the device polls the token endpoint with."],
        ["user_code", "Short human code the user types on a second device."],
        ["verification_uri", "URL the user visits to enter the user_code."],
        ["verification_uri_complete", "verification_uri with user_code embedded (for QR)."],
        ["expires_in", "Seconds until device_code/user_code expire."],
        ["interval", "Minimum seconds between token-endpoint polls (default 5)."],
        ["grant_type", "urn:ietf:params:oauth:grant-type:device_code when polling."],
      ];
      return refView(["Field / step", "Meaning"], rows, v.q);
    } },

  { id: "id-oidc-claims", name: "OpenID Connect Claim Reference", cat: "identity", desc: "Look up OpenID Connect standard claims (profile/email/address plus ID-token claims) and their meaning.", tags: ["oidc", "claims", "userinfo", "id token"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "sub, email, nonce" }],
    run(v) {
      const rows = [
        ["sub", "ID token", "Subject - unique, stable identifier for the user."],
        ["iss", "ID token", "Issuer identifier (the OP) that minted the token."],
        ["aud", "ID token", "Audience - client_id(s) the token is intended for."],
        ["exp", "ID token", "Expiration time (seconds since epoch)."],
        ["iat", "ID token", "Issued-at time."],
        ["auth_time", "ID token", "Time the end user was authenticated."],
        ["nonce", "ID token", "Value from the request, binds token to the session."],
        ["acr", "ID token", "Authentication Context Class Reference (assurance level)."],
        ["amr", "ID token", "Authentication Methods References (e.g. pwd, otp, mfa)."],
        ["azp", "ID token", "Authorized party - client the token was issued to."],
        ["at_hash", "ID token", "Hash of the access token (binds the two)."],
        ["name", "profile", "Full display name."],
        ["given_name", "profile", "First / given name."],
        ["family_name", "profile", "Last / family name."],
        ["preferred_username", "profile", "Shorthand name the user prefers (not unique)."],
        ["picture", "profile", "URL of the user's profile picture."],
        ["locale", "profile", "End user's locale (e.g. en-US)."],
        ["updated_at", "profile", "When the profile was last updated."],
        ["email", "email", "Preferred email address."],
        ["email_verified", "email", "Boolean: whether the email was verified."],
        ["phone_number", "phone", "Preferred phone number (E.164)."],
        ["phone_number_verified", "phone", "Boolean: whether the phone was verified."],
        ["address", "address", "JSON object with the user's postal address."],
      ];
      return refView(["Claim", "Scope/where", "Meaning"], rows, v.q);
    } },

  { id: "id-oidc-scopes", name: "OpenID Connect Scope Reference", cat: "identity", desc: "What each OpenID Connect scope requests and which claims it releases.", tags: ["oidc", "scope", "openid", "offline_access"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "profile, offline" }],
    run(v) {
      const rows = [
        ["openid", "Required to use OIDC; triggers issuing an ID token."],
        ["profile", "name, family_name, given_name, picture, locale, updated_at, ..."],
        ["email", "email, email_verified."],
        ["address", "address (structured postal address)."],
        ["phone", "phone_number, phone_number_verified."],
        ["offline_access", "Requests a refresh_token for access when the user is away."],
      ];
      return refView(["Scope", "Releases / effect"], rows, v.q);
    } },

  { id: "id-oidc-discovery", name: "OIDC Discovery Metadata Reference", cat: "identity", desc: "Fields of the OpenID Provider metadata document at /.well-known/openid-configuration.", tags: ["oidc", "discovery", "well-known", "metadata"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "jwks, endpoint" }],
    run(v) {
      const rows = [
        ["issuer", "The OP's issuer identifier URL (must match the id_token iss)."],
        ["authorization_endpoint", "Where authorization requests are sent."],
        ["token_endpoint", "Where tokens are obtained/refreshed."],
        ["userinfo_endpoint", "Returns claims about the authenticated user."],
        ["jwks_uri", "URL of the JSON Web Key Set used to verify signatures."],
        ["registration_endpoint", "Dynamic client registration endpoint."],
        ["end_session_endpoint", "RP-initiated logout endpoint."],
        ["introspection_endpoint", "RFC 7662 token introspection."],
        ["revocation_endpoint", "RFC 7009 token revocation."],
        ["scopes_supported", "Scopes the OP advertises."],
        ["response_types_supported", "response_type values the OP accepts."],
        ["grant_types_supported", "grant_type values the OP accepts."],
        ["subject_types_supported", "public or pairwise subject identifiers."],
        ["id_token_signing_alg_values_supported", "JWS algs used to sign ID tokens."],
        ["token_endpoint_auth_methods_supported", "How clients authenticate (e.g. client_secret_basic)."],
        ["code_challenge_methods_supported", "PKCE methods (S256, plain)."],
        ["claims_supported", "Claim names the OP may return."],
      ];
      return refView(["Metadata field", "Meaning"], rows, v.q);
    } },

  { id: "id-token-introspect", name: "Token Introspection Field Reference", cat: "identity", desc: "Fields of an OAuth 2.0 token introspection response (RFC 7662).", tags: ["oauth", "introspection", "rfc7662", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "active, scope" }],
    run(v) {
      const rows = [
        ["active", "Boolean - the only required field; true if the token is valid."],
        ["scope", "Space-separated list of scopes granted to the token."],
        ["client_id", "Client the token was issued to."],
        ["username", "Human-readable identifier of the resource owner."],
        ["token_type", "Type of the token (e.g. Bearer)."],
        ["exp", "Expiration (seconds since epoch)."],
        ["iat", "Issued-at time."],
        ["nbf", "Not-before time."],
        ["sub", "Subject of the token."],
        ["aud", "Intended audience."],
        ["iss", "Issuer of the token."],
        ["jti", "Unique token identifier."],
      ];
      return refView(["Field", "Meaning"], rows, v.q);
    } },

  // ---------------- JWT / JOSE ----------------
  { id: "id-jwt-claims", name: "JWT Registered Claim Reference", cat: "identity", desc: "The registered JWT claim names from RFC 7519 and what each means.", tags: ["jwt", "claims", "rfc7519", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "exp, aud" }],
    run(v) {
      const rows = [
        ["iss", "Issuer", "Principal that issued the JWT."],
        ["sub", "Subject", "Principal the JWT is about (the user)."],
        ["aud", "Audience", "Recipients the JWT is intended for."],
        ["exp", "Expiration Time", "Must not be accepted on/after this time (NumericDate)."],
        ["nbf", "Not Before", "Must not be accepted before this time."],
        ["iat", "Issued At", "Time the JWT was issued."],
        ["jti", "JWT ID", "Unique identifier, used to prevent replay."],
      ];
      return refView(["Claim", "Name", "Meaning"], rows, v.q);
    } },

  { id: "id-jwt-headers", name: "JOSE Header Parameter Reference", cat: "identity", desc: "JOSE/JWS/JWE header parameters (alg, kid, jku, x5c, crit, ...) and what each does.", tags: ["jose", "jws", "jwe", "header", "kid"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "kid, x5c" }],
    run(v) {
      const rows = [
        ["alg", "Signature or encryption algorithm (e.g. RS256, ES256, none)."],
        ["typ", "Media type of the token, usually JWT (or at+jwt for access tokens)."],
        ["cty", "Content type for nested JWTs."],
        ["kid", "Key ID - which key (in the JWKS) signed/encrypted the token."],
        ["jku", "URL of a JWK Set to fetch the key (SSRF/key-confusion risk)."],
        ["jwk", "Embedded public JSON Web Key (dangerous if trusted blindly)."],
        ["x5u", "URL of an X.509 certificate/chain."],
        ["x5c", "X.509 certificate chain (base64 DER array)."],
        ["x5t", "SHA-1 thumbprint of the X.509 certificate."],
        ["x5t#S256", "SHA-256 thumbprint of the X.509 certificate."],
        ["crit", "Header params that MUST be understood or the token rejected."],
        ["enc", "(JWE) content encryption algorithm, e.g. A256GCM."],
        ["zip", "(JWE) compression applied before encryption (DEF)."],
      ];
      return refView(["Parameter", "Meaning"], rows, v.q);
    } },

  { id: "id-jwt-alg", name: "JWS / JWT Algorithm Reference", cat: "identity", desc: "The alg values for JWT signatures (RFC 7518 + EdDSA) with key type and notes.", tags: ["jwt", "jws", "alg", "rs256", "es256", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "ES256, none" }],
    run(v) {
      const rows = [
        ["HS256", "HMAC + SHA-256", "Symmetric; shared secret. Watch for weak secrets."],
        ["HS384", "HMAC + SHA-384", "Symmetric."],
        ["HS512", "HMAC + SHA-512", "Symmetric."],
        ["RS256", "RSASSA-PKCS1-v1_5 + SHA-256", "Asymmetric; most common for OIDC."],
        ["RS384", "RSASSA-PKCS1-v1_5 + SHA-384", "Asymmetric."],
        ["RS512", "RSASSA-PKCS1-v1_5 + SHA-512", "Asymmetric."],
        ["PS256", "RSASSA-PSS + SHA-256", "Asymmetric; PSS padding (preferred over RS*)."],
        ["PS384", "RSASSA-PSS + SHA-384", "Asymmetric."],
        ["PS512", "RSASSA-PSS + SHA-512", "Asymmetric."],
        ["ES256", "ECDSA P-256 + SHA-256", "Asymmetric; compact signatures."],
        ["ES384", "ECDSA P-384 + SHA-384", "Asymmetric."],
        ["ES512", "ECDSA P-521 + SHA-512", "Asymmetric (note: P-521)."],
        ["EdDSA", "Ed25519 / Ed448", "Asymmetric; RFC 8037."],
        ["none", "Unsecured (no signature)", "DANGER: only valid for already-trusted tokens; key-confusion attacks."],
      ];
      return refView(["alg", "Algorithm", "Notes"], rows, v.q);
    } },

  { id: "id-jwk-fields", name: "JWK / JWKS Field Reference", cat: "identity", desc: "JSON Web Key members for RSA, EC, OKP and oct keys (RFC 7517/7518/8037).", tags: ["jwk", "jwks", "kty", "key", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "kty, crv" }],
    run(v) {
      const rows = [
        ["kty", "any", "Key type: RSA, EC, OKP or oct."],
        ["use", "any", "Public key use: sig (signature) or enc (encryption)."],
        ["key_ops", "any", "Allowed operations (sign, verify, encrypt, ...)."],
        ["alg", "any", "Algorithm intended for use with the key."],
        ["kid", "any", "Key ID, matches the JWS/JWT kid header."],
        ["n", "RSA", "Modulus (base64url)."],
        ["e", "RSA", "Public exponent (base64url, usually AQAB = 65537)."],
        ["d", "RSA/EC/OKP", "Private key material (PRIVATE - never publish)."],
        ["crv", "EC/OKP", "Curve: P-256, P-384, P-521, Ed25519, X25519."],
        ["x", "EC/OKP", "X coordinate / public key (base64url)."],
        ["y", "EC", "Y coordinate (base64url)."],
        ["k", "oct", "Symmetric key value (PRIVATE)."],
        ["x5c", "any", "X.509 certificate chain for the key."],
      ];
      return refView(["Member", "Key type", "Meaning"], rows, v.q);
    } },

  // ---------------- OTP ----------------
  { id: "id-hotp", name: "HOTP Code Generator (RFC 4226)", cat: "identity", desc: "Compute a counter-based HMAC-OTP from a Base32 secret and counter (RFC 4226).", tags: ["hotp", "otp", "rfc4226", "2fa"], button: "Compute", live: false,
    inputs: [
      { k: "secret", label: "Base32 secret", type: "text", placeholder: "GEZDGNBVGY3TQOJQ..." },
      { k: "counter", label: "Counter", type: "text", inputType: "number", value: "0" },
      { k: "digits", label: "Digits", type: "select", opts: ["6", "7", "8"], value: "6" },
      { k: "algo", label: "HMAC hash", type: "select", opts: ["SHA-1", "SHA-256", "SHA-512"], value: "SHA-1" },
    ],
    async run(v) {
      if (!S(v.secret).trim()) return "";
      const key = b32decode(v.secret);
      if (!key || !key.length) return { error: "Secret is not valid Base32 (A-Z, 2-7)." };
      const counter = BigInt(Math.trunc(Number(v.counter) || 0));
      if (counter < 0n) return { error: "Counter must be zero or positive." };
      const digits = parseInt(v.digits, 10);
      const h = await hmacBytes(v.algo, key, u64be(counter));
      const off = h[h.length - 1] & 0x0f;
      const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
      const code = (bin % 10 ** digits).toString().padStart(digits, "0");
      return `HOTP: ${code}\n\ncounter:    ${counter}\ndigits:     ${digits}\nhash:       ${v.algo}\nkey bytes:  ${key.length}`;
    } },

  { id: "id-otpauth-parse", name: "otpauth:// URI Parser", cat: "identity", desc: "Parse an otpauth:// provisioning URI (the QR payload) into its label, secret and parameters.", tags: ["otpauth", "totp", "hotp", "qr", "2fa"],
    inputs: [{ k: "uri", label: "otpauth:// URI", type: "textarea", rows: 2, placeholder: "otpauth://totp/Example:alice@example.com?secret=..." }],
    run(v) {
      const uri = S(v.uri).trim();
      if (!uri) return "";
      const m = uri.match(/^otpauth:\/\/(totp|hotp)\/([^?]*)(?:\?(.*))?$/i);
      if (!m) return { error: "Not an otpauth:// URI (expected otpauth://totp/... or hotp)." };
      const type = m[1].toLowerCase();
      let label = decodeURIComponent(m[2] || "");
      const params = {};
      S(m[3]).split("&").forEach((kv) => { if (!kv) return; const i = kv.indexOf("="); const k = decodeURIComponent(kv.slice(0, i < 0 ? kv.length : i)); const val = i < 0 ? "" : decodeURIComponent(kv.slice(i + 1)); params[k] = val; });
      let issuer = params.issuer || "", account = label;
      if (label.includes(":")) { const p = label.split(":"); issuer = issuer || p[0].trim(); account = p.slice(1).join(":").trim(); }
      const out = [["type", type], ["issuer", issuer || "(none)"], ["account", account || "(none)"], ["secret", params.secret || "(missing!)"], ["algorithm", params.algorithm || "SHA1 (default)"], ["digits", params.digits || "6 (default)"]];
      if (type === "totp") out.push(["period", params.period || "30 (default)"]);
      if (type === "hotp") out.push(["counter", params.counter || "(required for HOTP!)"]);
      return table(out);
    } },

  { id: "id-base32-secret", name: "TOTP Base32 Secret Formatter", cat: "identity", desc: "Validate a Base32 2FA secret and format it into readable groups, showing the decoded byte length.", tags: ["base32", "totp", "secret", "2fa"],
    inputs: [
      { k: "secret", label: "Base32 secret", type: "text", placeholder: "JBSWY3DPEHPK3PXP" },
      { k: "group", label: "Group size", type: "select", opts: ["4", "5", "8"], value: "4" },
    ],
    run(v) {
      const raw = S(v.secret).trim();
      if (!raw) return "";
      const clean = raw.toUpperCase().replace(/[\s=-]/g, "");
      const bad = clean.replace(/[A-Z2-7]/g, "");
      if (bad) return { error: `Invalid Base32 character(s): ${[...new Set(bad)].join(" ")} (allowed A-Z and 2-7).` };
      const bytes = b32decode(clean);
      const g = parseInt(v.group, 10);
      const grouped = clean.replace(new RegExp(`(.{${g}})`, "g"), "$1 ").trim();
      return `Valid Base32.\n\nformatted:  ${grouped}\nchars:      ${clean.length}\nbytes:      ${bytes.length}  (${bytes.length * 8} bits of key material)\nrecommend:  >= 16 bytes (128 bits) for TOTP`;
    } },

  { id: "id-totp-window", name: "TOTP Time-Step Calculator", cat: "identity", desc: "For a given Unix time, compute the TOTP counter (T), the HMAC message hex, and the window start/end (RFC 6238). No secret needed.", tags: ["totp", "rfc6238", "time step", "counter"],
    inputs: [
      { k: "time", label: "Unix time (blank = now)", type: "text", inputType: "number", placeholder: "1111111109" },
      { k: "period", label: "Period (seconds)", type: "text", inputType: "number", value: "30" },
      { k: "t0", label: "T0 epoch offset", type: "text", inputType: "number", value: "0" },
    ],
    run(v) {
      const now = S(v.time).trim() ? Math.trunc(Number(v.time)) : Math.floor(Date.now() / 1000);
      if (!isFinite(now)) return { error: "Unix time must be a number." };
      const period = Math.trunc(Number(v.period) || 30);
      const t0 = Math.trunc(Number(v.t0) || 0);
      if (period <= 0) return { error: "Period must be positive." };
      const T = Math.floor((now - t0) / period);
      const start = t0 + T * period, end = start + period;
      const hex = T.toString(16).padStart(16, "0").toUpperCase();
      return `unix time:   ${now}\ncounter T:   ${T}\nT (hex msg): ${hex}\nwindow:      ${start} .. ${end - 1}\n  start UTC: ${new Date(start * 1000).toISOString()}\n  end UTC:   ${new Date(end * 1000).toISOString()}\nelapsed:     ${now - start}s into step\nremaining:   ${end - now}s`;
    } },

  // ---------------- SAML ----------------
  { id: "id-saml-decode", name: "SAML Message Decoder", cat: "identity", desc: "Decode a SAML Request/Response: Base64 (HTTP-POST) or URL-encoded Base64 + raw DEFLATE (HTTP-Redirect), then pretty-print the XML.", tags: ["saml", "sso", "inflate", "deflate", "base64"], button: "Decode",
    inputs: [
      { k: "data", label: "SAMLRequest / SAMLResponse value", type: "textarea", rows: 5, placeholder: "fZJ...=" },
      { k: "mode", label: "Binding", type: "select", opts: ["Auto-detect", "HTTP-Redirect (inflate)", "HTTP-POST (base64 only)"], value: "Auto-detect" },
    ],
    run(v) {
      const raw = S(v.data).trim();
      if (!raw) return "";
      let data = raw;
      if (/%[0-9a-fA-F]{2}/.test(data)) { try { data = decodeURIComponent(data); } catch (e) { /* keep */ } }
      let bytes;
      try { bytes = b64bytes(data); } catch (e) { return { error: "Input is not valid Base64." }; }
      const looksXml = (u) => { let i = 0; while (i < u.length && (u[i] === 0x20 || u[i] === 0x09 || u[i] === 0x0a || u[i] === 0x0d || u[i] === 0xef || u[i] === 0xbb || u[i] === 0xbf)) i++; return u[i] === 0x3c; };
      let xmlBytes = bytes, note = "";
      const wantInflate = v.mode === "HTTP-Redirect (inflate)" || (v.mode === "Auto-detect" && !looksXml(bytes));
      if (wantInflate) {
        try { xmlBytes = inflateRaw(bytes); note = "(decompressed raw DEFLATE / HTTP-Redirect binding)"; }
        catch (e) { if (looksXml(bytes)) { xmlBytes = bytes; note = "(plain Base64 / HTTP-POST binding)"; } else return { error: "Base64 decoded but raw DEFLATE inflate failed. If this is an HTTP-POST SAMLResponse, choose that binding." }; }
      } else note = "(plain Base64 / HTTP-POST binding)";
      const xml = new TextDecoder().decode(xmlBytes);
      if (!xml.includes("<")) return { error: "Decoded output does not look like XML." };
      return `${note}\n\n${prettyXml(xml)}`;
    } },

  { id: "id-saml-ref", name: "SAML 2.0 Element Reference", cat: "identity", desc: "Key SAML 2.0 protocol/assertion elements and what they carry.", tags: ["saml", "assertion", "sso", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "Assertion, NameID" }],
    run(v) {
      const rows = [
        ["samlp:AuthnRequest", "SP -> IdP request to authenticate a user."],
        ["samlp:Response", "IdP -> SP response, wraps status and assertion(s)."],
        ["samlp:Status / StatusCode", "Success/failure of the request (e.g. urn:...:status:Success)."],
        ["saml:Assertion", "The signed statement about the subject (the core of SSO)."],
        ["saml:Issuer", "Entity ID of the party that issued the message/assertion."],
        ["saml:Subject", "The principal the assertion is about."],
        ["saml:NameID", "Identifier for the subject (email, persistent, transient...)."],
        ["saml:Conditions", "Validity window (NotBefore/NotOnOrAfter) and audience."],
        ["saml:AudienceRestriction", "SP entity ID the assertion is intended for."],
        ["saml:AuthnStatement", "How/when the subject authenticated (AuthnContext)."],
        ["saml:AttributeStatement", "Container of user attributes (claims)."],
        ["saml:Attribute / AttributeValue", "A single attribute name and its value(s)."],
        ["ds:Signature", "XML-DSig over the response and/or assertion."],
      ];
      return refView(["Element", "Meaning"], rows, v.q);
    } },

  { id: "id-saml-bindings", name: "SAML 2.0 Binding Reference", cat: "identity", desc: "SAML 2.0 protocol bindings and their binding URIs.", tags: ["saml", "binding", "redirect", "post", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "Redirect, POST" }],
    run(v) {
      const rows = [
        ["HTTP-Redirect", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect", "Base64 + raw DEFLATE in a URL query param; for short messages."],
        ["HTTP-POST", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", "Base64 (no deflate) in an auto-submitting HTML form."],
        ["HTTP-Artifact", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact", "Small artifact reference resolved out-of-band."],
        ["SOAP", "urn:oasis:names:tc:SAML:2.0:bindings:SOAP", "Back-channel SOAP (artifact resolution, logout)."],
        ["PAOS", "urn:oasis:names:tc:SAML:2.0:bindings:PAOS", "Reverse SOAP for ECP (non-browser) clients."],
      ];
      return refView(["Binding", "URI", "Notes"], rows, v.q);
    } },

  // ---------------- Credential storage / passwords ----------------
  { id: "id-phc-parse", name: "PHC Hash String Parser", cat: "identity", desc: "Parse a PHC-format password hash ($argon2id$, $scrypt$, $pbkdf2$, ...) into its algorithm, parameters, salt and digest. No verification.", tags: ["argon2", "scrypt", "pbkdf2", "phc", "password"],
    inputs: [{ k: "hash", label: "PHC string", type: "textarea", rows: 2, placeholder: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$..." }],
    run(v) {
      const h = S(v.hash).trim();
      if (!h) return "";
      if (h[0] !== "$") return { error: "Not a PHC string (must start with $id$...)." };
      const parts = h.split("$"); // ["", id, (v=..)?, (params)?, salt?, hash?]
      parts.shift();
      const id = parts.shift();
      const names = { argon2id: "Argon2id", argon2i: "Argon2i", argon2d: "Argon2d", scrypt: "scrypt", pbkdf2: "PBKDF2", "pbkdf2-sha256": "PBKDF2-HMAC-SHA256", "pbkdf2-sha512": "PBKDF2-HMAC-SHA512", bcrypt: "bcrypt", "argon2": "Argon2" };
      const out = [["algorithm", names[id] || id]];
      let version = null, params = null, salt = null, digest = null;
      const rest = [];
      for (const p of parts) rest.push(p);
      // optional version: v=NN
      let idx = 0;
      if (rest[idx] && /^v=\d+$/.test(rest[idx])) { version = rest[idx].slice(2); idx++; }
      // optional params: contains '='
      if (rest[idx] && rest[idx].includes("=")) { params = rest[idx]; idx++; }
      if (rest[idx] !== undefined) { salt = rest[idx]; idx++; }
      if (rest[idx] !== undefined) { digest = rest[idx]; idx++; }
      if (version) out.push(["version", version + (version === "19" ? " (0x13)" : "")]);
      if (params) {
        const pm = {};
        params.split(",").forEach((kv) => { const [k, val] = kv.split("="); pm[k] = val; });
        const label = { m: "memory (KiB)", t: "iterations/time", p: "parallelism", ln: "cost log2(N)", r: "block size r", i: "iterations", rounds: "rounds", keylen: "key length" };
        for (const [k, val] of Object.entries(pm)) out.push([`param ${k}`, `${val}${label[k] ? "  (" + label[k] + ")" : ""}`]);
      }
      out.push(["salt (b64)", salt || "(none)"]);
      if (salt) { try { out.push(["salt bytes", String(b64bytes(salt.replace(/-/g, "+").replace(/_/g, "/")).length)]); } catch (e) { /* nonstandard */ } }
      out.push(["hash (b64)", digest ? (digest.length > 44 ? digest.slice(0, 44) + "..." : digest) : "(none)"]);
      return table(out) + "\n\nNote: parsed only - this does NOT verify any password.";
    } },

  { id: "id-crypt-scheme", name: "Unix crypt(3) Scheme Identifier", cat: "identity", desc: "Identify the hashing scheme of a Unix crypt / Modular Crypt Format password hash by its prefix.", tags: ["crypt", "mcf", "shadow", "password", "hash"],
    inputs: [{ k: "hash", label: "Hash field", type: "text", placeholder: "$6$rounds=5000$salt$..." }],
    run(v) {
      const h = S(v.hash).trim();
      if (!h) return "";
      const map = [
        [/^\$1\$/, "md5crypt (MD5-based, $1$)"],
        [/^\$2[abxy]?\$/, "bcrypt (Blowfish, $2a/2b/2y$)"],
        [/^\$5\$/, "sha256crypt ($5$)"],
        [/^\$6\$/, "sha512crypt ($6$) - common Linux /etc/shadow default"],
        [/^\$y\$/, "yescrypt ($y$) - modern Linux default"],
        [/^\$gy\$/, "gost-yescrypt ($gy$)"],
        [/^\$7\$/, "scrypt ($7$)"],
        [/^\$argon2(id|i|d)\$/, "Argon2 (PHC format)"],
        [/^\$pbkdf2(-sha\d+)?\$/, "PBKDF2 (PHC/passlib format)"],
        [/^\$md5\$/, "Sun MD5 crypt ($md5$)"],
        [/^\$sha1\$/, "PBKDF2-HMAC-SHA1 ($sha1$)"],
        [/^_/, "BSDi extended DES (underscore prefix)"],
        [/^\{[A-Z0-9]+\}/, "LDAP/RFC 2307 scheme (e.g. {SSHA}, {CRYPT})"],
      ];
      for (const [re, name] of map) if (re.test(h)) return `Scheme: ${name}`;
      if (/^[./0-9A-Za-z]{13}$/.test(h)) return "Scheme: traditional DES crypt (13 chars, no prefix) - very weak/legacy";
      return { error: "Unrecognised crypt scheme / prefix." };
    } },

  { id: "id-shadow-parse", name: "/etc/shadow Line Parser", cat: "identity", desc: "Break an /etc/shadow entry into its fields and interpret the password-aging columns and lock state.", tags: ["shadow", "linux", "password", "aging"],
    inputs: [{ k: "line", label: "shadow line", type: "textarea", rows: 2, placeholder: "alice:$6$...:19000:0:99999:7:::" }],
    run(v) {
      const line = S(v.line).trim();
      if (!line) return "";
      const f = line.split(":");
      if (f.length < 2) return { error: "Not a shadow line (expected colon-separated fields)." };
      const pw = f[1] || "";
      let state = "has a hash";
      if (pw === "" ) state = "empty - no password required (risky)";
      else if (pw === "*" ) state = "login disabled (no valid hash, '*')";
      else if (pw === "!" || pw === "!!") state = "locked / no password set";
      else if (pw[0] === "!") state = "LOCKED (hash present but prefixed with '!')";
      const day = (n) => { const d = parseInt(n, 10); return isNaN(d) ? n : `${d} (${new Date(d * 86400000).toISOString().slice(0, 10)})`; };
      const names = ["username", "password", "last change (days since epoch)", "min age (days)", "max age (days)", "warn (days)", "inactive (days)", "expire (days since epoch)", "reserved"];
      const out = [];
      f.forEach((val, i) => { let shown = val === "" ? "(empty)" : val; if (i === 2 || i === 7) shown = val === "" ? "(empty)" : day(val); out.push([names[i] || `field ${i}`, shown]); });
      out.push(["-> password state", state]);
      return table(out);
    } },

  { id: "id-passwd-parse", name: "/etc/passwd Line Parser", cat: "identity", desc: "Break an /etc/passwd entry into fields and flag login shell and account type from the UID.", tags: ["passwd", "linux", "uid", "account"],
    inputs: [{ k: "line", label: "passwd line", type: "text", placeholder: "alice:x:1000:1000:Alice,,,:/home/alice:/bin/bash" }],
    run(v) {
      const line = S(v.line).trim();
      if (!line) return "";
      const f = line.split(":");
      if (f.length < 7) return { error: "Expected 7 colon-separated fields (user:pw:uid:gid:gecos:home:shell)." };
      const [user, pw, uid, gid, gecos, home, shell] = f;
      const n = parseInt(uid, 10);
      let kind = "regular user (UID >= 1000)";
      if (n === 0) kind = "ROOT (UID 0) - superuser";
      else if (n < 1000) kind = "system/service account (UID < 1000)";
      const noLogin = /(nologin|false)$/.test(shell || "");
      const out = [
        ["username", user], ["password field", pw === "x" ? "x (hash in /etc/shadow)" : pw],
        ["UID", `${uid}  -> ${kind}`], ["GID", gid], ["GECOS/comment", gecos || "(empty)"],
        ["home", home], ["shell", `${shell}${noLogin ? "  -> login disabled" : ""}`],
      ];
      return table(out);
    } },

  { id: "id-htpasswd-parse", name: "htpasswd Line Parser", cat: "identity", desc: "Parse an Apache htpasswd line into user and hash, and identify the hashing scheme. No verification.", tags: ["htpasswd", "apache", "basic auth", "hash"],
    inputs: [{ k: "line", label: "htpasswd line", type: "text", placeholder: "admin:$apr1$...." }],
    run(v) {
      const line = S(v.line).trim();
      if (!line) return "";
      const i = line.indexOf(":");
      if (i < 0) return { error: "Expected user:hash (colon separated)." };
      const user = line.slice(0, i), hash = line.slice(i + 1);
      let scheme = "unknown";
      if (/^\$apr1\$/.test(hash)) scheme = "apr1 (Apache MD5) - htpasswd -m";
      else if (/^\$2[aby]?\$/.test(hash)) scheme = "bcrypt - htpasswd -B (strongest)";
      else if (/^\{SHA\}/.test(hash)) scheme = "SHA-1 (base64) - htpasswd -s (weak, unsalted)";
      else if (/^\$1\$/.test(hash)) scheme = "md5crypt ($1$)";
      else if (/^[./0-9A-Za-z]{13}$/.test(hash)) scheme = "crypt DES (13 chars) - htpasswd -d (very weak)";
      else scheme = "plaintext or unrecognised - htpasswd -p?";
      return table([["user", user], ["hash", hash.length > 50 ? hash.slice(0, 50) + "..." : hash], ["scheme", scheme]]);
    } },

  { id: "id-digest-auth", name: "HTTP Digest Auth Response Calculator", cat: "identity", desc: "Compute the HTTP Digest Access Authentication response hash and Authorization header (RFC 2617/7616, MD5).", tags: ["digest", "http auth", "rfc2617", "md5"], button: "Compute", live: false,
    inputs: [
      { k: "username", label: "username", type: "text", placeholder: "Mufasa" },
      { k: "password", label: "password", type: "text", placeholder: "Circle Of Life" },
      { k: "realm", label: "realm", type: "text", placeholder: "testrealm@host.com" },
      { k: "method", label: "HTTP method", type: "select", opts: ["GET", "POST", "PUT", "DELETE", "HEAD"], value: "GET" },
      { k: "uri", label: "digest-uri", type: "text", placeholder: "/dir/index.html" },
      { k: "nonce", label: "nonce", type: "text", placeholder: "dcd98b7102dd2f0e8b11d0f600bfb0c093" },
      { k: "qop", label: "qop", type: "select", opts: ["(none)", "auth"], value: "auth" },
      { k: "nc", label: "nc (nonce count)", type: "text", value: "00000001" },
      { k: "cnonce", label: "cnonce", type: "text", placeholder: "0a4f113b" },
    ],
    run(v, H) {
      if (!S(v.username) || !S(v.realm) || !S(v.nonce) || !S(v.uri)) return "";
      const ha1 = H.md5(`${v.username}:${v.realm}:${v.password}`);
      const ha2 = H.md5(`${v.method}:${v.uri}`);
      let response, header;
      if (v.qop === "auth") {
        if (!S(v.cnonce)) return { error: "qop=auth requires a cnonce." };
        response = H.md5(`${ha1}:${v.nonce}:${v.nc}:${v.cnonce}:auth:${ha2}`);
        header = `Authorization: Digest username="${v.username}", realm="${v.realm}", nonce="${v.nonce}", uri="${v.uri}", qop=auth, nc=${v.nc}, cnonce="${v.cnonce}", response="${response}"`;
      } else {
        response = H.md5(`${ha1}:${v.nonce}:${ha2}`);
        header = `Authorization: Digest username="${v.username}", realm="${v.realm}", nonce="${v.nonce}", uri="${v.uri}", response="${response}"`;
      }
      return `HA1:      ${ha1}\nHA2:      ${ha2}\nresponse: ${response}\n\n${header}`;
    } },

  { id: "id-keyspace", name: "Password Keyspace & Crack-Time Estimator", cat: "identity", desc: "Estimate the keyspace, entropy and offline crack time for a password policy (character set + length), given a guess rate.", tags: ["password", "entropy", "keyspace", "crack time"],
    inputs: [
      { k: "length", label: "Password length", type: "text", inputType: "number", value: "12" },
      { k: "lower", label: "lowercase a-z (26)", type: "checkbox", value: true },
      { k: "upper", label: "UPPERCASE A-Z (26)", type: "checkbox", value: true },
      { k: "digits", label: "digits 0-9 (10)", type: "checkbox", value: true },
      { k: "symbols", label: "symbols (32)", type: "checkbox", value: false },
      { k: "rate", label: "Guesses / second", type: "text", placeholder: "1e9", value: "1e9" },
    ],
    run(v) {
      const len = Math.trunc(Number(v.length) || 0);
      if (len <= 0) return { error: "Length must be a positive number." };
      let n = 0;
      if (v.lower) n += 26;
      if (v.upper) n += 26;
      if (v.digits) n += 10;
      if (v.symbols) n += 32;
      if (!n) return { error: "Select at least one character set." };
      const rate = Number(v.rate) || 1e9;
      const bits = len * Math.log2(n);
      const combos = Math.pow(n, len);
      const avgSeconds = (combos / 2) / rate;
      return [
        `charset size:   ${n}`,
        `length:         ${len}`,
        `entropy:        ${bits.toFixed(1)} bits`,
        `combinations:   ${combos === Infinity ? "> 1e308" : combos.toExponential(2)}`,
        `guess rate:     ${rate.toExponential(1)} /s`,
        `avg crack time: ${humanDuration(avgSeconds)}`,
        "",
        "Theoretical keyspace only - real passwords are weaker if guessable.",
      ].join("\n");
    } },

  // ---------------- Kerberos ----------------
  { id: "id-kerberos-etype", name: "Kerberos Encryption Type Reference", cat: "identity", desc: "Kerberos etype numbers, their algorithms and security notes (roasting relevance).", tags: ["kerberos", "etype", "rc4", "aes", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "aes, rc4, 23" }],
    run(v) {
      const rows = [
        ["1", "des-cbc-crc", "DES - broken, legacy only."],
        ["3", "des-cbc-md5", "DES - broken, legacy only."],
        ["16", "des3-cbc-sha1", "Triple DES - deprecated."],
        ["17", "aes128-cts-hmac-sha1-96", "AES-128 - modern, preferred."],
        ["18", "aes256-cts-hmac-sha1-96", "AES-256 - modern, preferred."],
        ["19", "aes128-cts-hmac-sha256-128", "AES-128 + SHA-256 (RFC 8009)."],
        ["20", "aes256-cts-hmac-sha384-192", "AES-256 + SHA-384 (RFC 8009)."],
        ["23", "rc4-hmac (arcfour-hmac)", "RC4; NT hash as key - Kerberoasting-friendly, disable it."],
        ["24", "rc4-hmac-exp", "Export RC4 - broken."],
      ];
      return refView(["etype", "Algorithm", "Notes"], rows, v.q);
    } },

  { id: "id-kerberos-spn", name: "Kerberos SPN Format Explainer", cat: "identity", desc: "Parse a Service Principal Name (serviceclass/host[:port][/name]) into parts and show common service classes.", tags: ["kerberos", "spn", "serviceprincipalname", "ad"],
    inputs: [{ k: "spn", label: "SPN", type: "text", placeholder: "MSSQLSvc/db01.example.com:1433" }],
    run(v) {
      const spn = S(v.spn).trim();
      const common = "Common service classes: HOST (any service on the host), HTTP (web/WinRM),\nCIFS (file shares), LDAP (directory), MSSQLSvc (SQL Server), TERMSRV (RDP),\nWSMAN (WinRM), DNS, GC (global catalog), krbtgt (the KDC).";
      if (!spn) return "Format: serviceclass/hostname[:port][/servicename][@REALM]\n\n" + common;
      let realm = "";
      let core = spn;
      const at = spn.indexOf("@");
      if (at >= 0) { realm = spn.slice(at + 1); core = spn.slice(0, at); }
      const seg = core.split("/");
      if (seg.length < 2) return { error: "SPN must be serviceclass/host (e.g. HTTP/web01.example.com)." };
      const serviceClass = seg[0];
      let host = seg[1], port = "", name = seg[2] || "";
      const c = host.indexOf(":");
      if (c >= 0) { port = host.slice(c + 1); host = host.slice(0, c); }
      const out = [["service class", serviceClass], ["host / instance", host]];
      if (port) out.push(["port", port]);
      if (name) out.push(["service name", name]);
      if (realm) out.push(["realm", realm]);
      return table(out) + "\n\n" + common;
    } },

  { id: "id-kerberos-flags", name: "Kerberos Ticket Flag Reference", cat: "identity", desc: "Kerberos ticket flag bit positions and meanings (RFC 4120), including delegation-relevant flags.", tags: ["kerberos", "ticket", "flags", "delegation", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "forwardable, delegate" }],
    run(v) {
      const rows = [
        ["1", "forwardable", "TGT may be used to get forwardable tickets (delegation)."],
        ["2", "forwarded", "This ticket was forwarded / issued from a forwardable TGT."],
        ["3", "proxiable", "May be used to obtain a proxy ticket."],
        ["4", "proxy", "This is a proxy ticket."],
        ["5", "may-postdate", "TGT may be used to issue postdated tickets."],
        ["6", "postdated", "Ticket starts validity in the future."],
        ["7", "invalid", "Ticket is invalid and must be validated by the KDC."],
        ["8", "renewable", "Ticket may be renewed."],
        ["9", "initial", "Issued by AS, not from a TGT (proves password/PKINIT)."],
        ["10", "pre-authent", "KDC performed pre-authentication."],
        ["11", "hw-authent", "Hardware-based pre-authentication was used."],
        ["13", "ok-as-delegate", "Service is trusted for (constrained) delegation."],
      ];
      return refView(["Bit", "Flag", "Meaning"], rows, v.q);
    } },

  { id: "id-kerberos-errors", name: "Kerberos Error Code Reference", cat: "identity", desc: "Common Kerberos KDC and AP error codes and what they indicate (RFC 4120).", tags: ["kerberos", "error", "kdc", "preauth", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "preauth, skew" }],
    run(v) {
      const rows = [
        ["6", "KDC_ERR_C_PRINCIPAL_UNKNOWN", "Client/user not found (used in user enumeration)."],
        ["7", "KDC_ERR_S_PRINCIPAL_UNKNOWN", "Service/server principal not found (bad SPN)."],
        ["12", "KDC_ERR_POLICY", "Request rejected by policy (e.g. logon hours)."],
        ["14", "KDC_ERR_ETYPE_NOSUPP", "No supported encryption type in common."],
        ["18", "KDC_ERR_CLIENT_REVOKED", "Account disabled, expired or locked out."],
        ["23", "KDC_ERR_KEY_EXPIRED", "Password has expired."],
        ["24", "KDC_ERR_PREAUTH_FAILED", "Wrong password (pre-auth failed)."],
        ["25", "KDC_ERR_PREAUTH_REQUIRED", "Pre-auth needed; absence enables AS-REP roasting."],
        ["31", "KRB_AP_ERR_BAD_INTEGRITY", "Decryption failed - wrong key/password."],
        ["32", "KRB_AP_ERR_TKT_EXPIRED", "Ticket expired."],
        ["37", "KRB_AP_ERR_SKEW", "Clock skew too great between client and KDC."],
        ["41", "KRB_AP_ERR_MODIFIED", "Ticket modified / wrong service key (SPN mismatch)."],
      ];
      return refView(["Code", "Name", "Meaning"], rows, v.q);
    } },

  // ---------------- LDAP / Active Directory ----------------
  { id: "id-ldap-dn-parse", name: "LDAP Distinguished Name Parser", cat: "identity", desc: "Split an LDAP/X.500 Distinguished Name into its RDN components, honouring escaping and multi-valued RDNs (RFC 4514).", tags: ["ldap", "dn", "rdn", "rfc4514", "ad"],
    inputs: [{ k: "dn", label: "Distinguished Name", type: "text", placeholder: "CN=John Doe,OU=Users,DC=example,DC=com" }],
    run(v) {
      const dn = S(v.dn).trim();
      if (!dn) return "";
      const rdns = splitEsc(dn, ",;").map((s) => s.trim()).filter(Boolean);
      if (!rdns.length) return { error: "Empty DN." };
      const out = [];
      rdns.forEach((rdn, i) => {
        const pairs = splitEsc(rdn, "+");
        pairs.forEach((p, j) => {
          const [a, val] = splitPairEsc(p.trim());
          if (val === null) { out.push([`RDN ${i + 1}`, `(malformed, no '='): ${p}`]); return; }
          out.push([`RDN ${i + 1}${pairs.length > 1 ? "." + (j + 1) : ""}`, `${a.trim()} = ${val.trim()}`]);
        });
      });
      const leaf = splitPairEsc(splitEsc(rdns[0], "+")[0].trim());
      return table(out) + `\n\ncomponents: ${rdns.length}\nleaf (most specific): ${leaf[0].trim()}=${S(leaf[1]).trim()}`;
    } },

  { id: "id-ldap-dn-escape", name: "LDAP DN Value Escaper", cat: "identity", desc: "Escape a value for safe use inside an LDAP Distinguished Name (RFC 4514 special characters and leading/trailing space/#).", tags: ["ldap", "dn", "escape", "rfc4514"],
    inputs: [{ k: "value", label: "Raw attribute value", type: "text", placeholder: "Doe, John" }],
    run(v) {
      const raw = S(v.value);
      if (!raw) return "";
      let out = raw.replace(/([\\",+;<>=])/g, "\\$1");
      out = out.replace(/^ /, "\\ ").replace(/^#/, "\\#").replace(/ $/, "\\ ");
      out = out.replace(/\x00/g, "\\00");
      return `escaped: ${out}\n\nUse as e.g.  CN=${out},OU=Users,DC=example,DC=com`;
    } },

  { id: "id-ldap-filter-escape", name: "LDAP Search Filter Escaper", cat: "identity", desc: "Escape a value for an LDAP search filter per RFC 4515 - prevents LDAP injection in queries.", tags: ["ldap", "filter", "injection", "rfc4515", "escape"],
    inputs: [{ k: "value", label: "Raw filter value", type: "text", placeholder: "a*(b)c\\d" }],
    run(v) {
      const raw = S(v.value);
      if (!raw) return "";
      const esc = raw.replace(/[\\*()\x00]/g, (c) => ({ "\\": "\\5c", "*": "\\2a", "(": "\\28", ")": "\\29", "\x00": "\\00" }[c]));
      return `escaped: ${esc}\n\nUse as e.g.  (uid=${esc})\nMappings: \\ -> \\5c   * -> \\2a   ( -> \\28   ) -> \\29   NUL -> \\00`;
    } },

  { id: "id-ldap-attrs", name: "LDAP / AD Attribute Reference", cat: "identity", desc: "Common LDAP and Active Directory attribute names and what they hold.", tags: ["ldap", "ad", "attribute", "samaccountname", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "sam, upn, sid" }],
    run(v) {
      const rows = [
        ["dn", "LDAP", "Distinguished Name - full path to the entry."],
        ["cn", "LDAP", "Common Name."],
        ["ou", "LDAP", "Organizational Unit."],
        ["dc", "LDAP", "Domain Component (e.g. dc=example,dc=com)."],
        ["uid", "LDAP", "User ID (login name on POSIX/openLDAP)."],
        ["sn / givenName", "LDAP", "Surname / first name."],
        ["mail", "LDAP", "Email address."],
        ["objectClass", "LDAP", "Structural/auxiliary classes of the entry."],
        ["member / memberOf", "LDAP", "Group membership (forward / back link)."],
        ["sAMAccountName", "AD", "Pre-Windows 2000 logon name (<= 20 chars)."],
        ["userPrincipalName", "AD", "UPN login (user@domain)."],
        ["distinguishedName", "AD", "Entry's DN."],
        ["userAccountControl", "AD", "Bit flags: disabled, no-preauth, delegation, ..."],
        ["objectSid", "AD", "Binary Security Identifier."],
        ["objectGUID", "AD", "Immutable globally unique identifier."],
        ["servicePrincipalName", "AD", "SPNs for Kerberos (Kerberoasting target)."],
        ["pwdLastSet", "AD", "When the password was last set (FILETIME)."],
        ["memberOf", "AD", "Groups the object belongs to."],
        ["adminCount", "AD", "1 if protected by AdminSDHolder (privileged)."],
      ];
      return refView(["Attribute", "Dir", "Meaning"], rows, v.q);
    } },

  { id: "id-ad-uac", name: "AD userAccountControl Decoder", cat: "identity", desc: "Decode an Active Directory userAccountControl integer into its flags, highlighting security-relevant bits.", tags: ["ad", "uac", "useraccountcontrol", "delegation", "preauth"],
    inputs: [{ k: "value", label: "userAccountControl (decimal or 0x hex)", type: "text", placeholder: "66048" }],
    run(v) {
      const raw = S(v.value).trim();
      if (!raw) return "";
      const n = /^0x/i.test(raw) ? parseInt(raw, 16) : parseInt(raw, 10);
      if (!isFinite(n) || n < 0) return { error: "Enter a non-negative integer (decimal or 0x hex)." };
      const flags = [
        [0x0001, "SCRIPT"], [0x0002, "ACCOUNTDISABLE"], [0x0008, "HOMEDIR_REQUIRED"], [0x0010, "LOCKOUT"],
        [0x0020, "PASSWD_NOTREQD *"], [0x0040, "PASSWD_CANT_CHANGE"], [0x0080, "ENCRYPTED_TEXT_PWD_ALLOWED"],
        [0x0100, "TEMP_DUPLICATE_ACCOUNT"], [0x0200, "NORMAL_ACCOUNT"], [0x0800, "INTERDOMAIN_TRUST_ACCOUNT"],
        [0x1000, "WORKSTATION_TRUST_ACCOUNT"], [0x2000, "SERVER_TRUST_ACCOUNT"], [0x10000, "DONT_EXPIRE_PASSWORD"],
        [0x20000, "MNS_LOGON_ACCOUNT"], [0x40000, "SMARTCARD_REQUIRED"], [0x80000, "TRUSTED_FOR_DELEGATION *"],
        [0x100000, "NOT_DELEGATED"], [0x200000, "USE_DES_KEY_ONLY *"], [0x400000, "DONT_REQ_PREAUTH *"],
        [0x800000, "PASSWORD_EXPIRED"], [0x1000000, "TRUSTED_TO_AUTH_FOR_DELEGATION *"], [0x4000000, "PARTIAL_SECRETS_ACCOUNT"],
      ];
      const set = flags.filter(([bit]) => (n & bit) === bit).map(([bit, name]) => [`0x${bit.toString(16).padStart(6, "0")}`, name]);
      if (!set.length) return `0x${n.toString(16)} (${n}) has no known flags set.`;
      return `value: ${n}  (0x${n.toString(16).toUpperCase()})\n\n` + table([["bit", "flag"], ...set]) + "\n\n* = commonly security-relevant (no-preauth, delegation, no-password).";
    } },

  { id: "id-upn-parse", name: "UPN / Logon Name Parser", cat: "identity", desc: "Parse a Windows UPN (user@domain) or down-level logon name (DOMAIN\\user) into its parts.", tags: ["ad", "upn", "logon", "netbios", "windows"],
    inputs: [{ k: "name", label: "Account name", type: "text", placeholder: "alice@example.com or EXAMPLE\\alice" }],
    run(v) {
      const name = S(v.name).trim();
      if (!name) return "";
      if (name.includes("@")) {
        const [u, d] = name.split("@");
        if (!u || !d) return { error: "UPN must be user@domain." };
        return table([["format", "UPN (RFC 822 style)"], ["user (prefix)", u], ["UPN suffix (domain)", d], ["down-level form", `<NETBIOS>\\${u}  (NetBIOS name not derivable from UPN)`]]);
      }
      if (name.includes("\\")) {
        const [d, u] = name.split("\\");
        if (!u) return { error: "Down-level name must be DOMAIN\\user." };
        return table([["format", "down-level logon (DOMAIN\\user)"], ["NetBIOS domain", d], ["user (SAMAccountName)", u], ["UPN form", `${u}@<upn-suffix>  (suffix not derivable from NetBIOS name)`]]);
      }
      return table([["format", "bare account name (no domain)"], ["name", name], ["note", "Add @domain for a UPN or DOMAIN\\ prefix for a down-level name."]]);
    } },

  // ---------------- Windows SIDs / RIDs ----------------
  { id: "id-well-known-rid", name: "Windows Well-Known RID Reference", cat: "identity", desc: "Well-known Active Directory Relative Identifiers (the tail of a domain SID) for built-in users and groups.", tags: ["windows", "ad", "rid", "sid", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "admin, krbtgt, 512" }],
    run(v) {
      const rows = [
        ["500", "Administrator", "Built-in domain administrator account."],
        ["501", "Guest", "Built-in guest account."],
        ["502", "krbtgt", "Kerberos ticket-granting account (Golden Ticket target)."],
        ["512", "Domain Admins", "Full control of the domain."],
        ["513", "Domain Users", "All domain user accounts."],
        ["514", "Domain Guests", "Domain guest accounts."],
        ["515", "Domain Computers", "All domain-joined computers."],
        ["516", "Domain Controllers", "All domain controllers."],
        ["517", "Cert Publishers", "Can publish certificates to AD."],
        ["518", "Schema Admins", "Can modify the AD schema (forest-wide)."],
        ["519", "Enterprise Admins", "Forest-wide administration (most powerful)."],
        ["520", "Group Policy Creator Owners", "Can create Group Policy Objects."],
        ["521", "Read-only Domain Controllers", "RODC group."],
        ["525", "Protected Users", "Enhanced credential protections."],
        ["526", "Key Admins", "Manage msDS-KeyCredentialLink (key trust)."],
        ["527", "Enterprise Key Admins", "Forest-wide key administration."],
      ];
      return refView(["RID", "Principal", "Meaning"], rows, v.q);
    } },

  { id: "id-well-known-sid", name: "Windows Well-Known SID Reference", cat: "identity", desc: "Well-known Windows Security Identifiers (SIDs) for built-in accounts, groups and logon types.", tags: ["windows", "sid", "everyone", "system", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "system, everyone" }],
    run(v) {
      const rows = [
        ["S-1-0-0", "Nobody", "Null SID."],
        ["S-1-1-0", "Everyone", "All users including anonymous (on some configs)."],
        ["S-1-2-0", "Local", "Users who log on locally."],
        ["S-1-3-0", "Creator Owner", "Placeholder replaced by the creator's SID."],
        ["S-1-5-2", "Network", "Logged on over the network."],
        ["S-1-5-4", "Interactive", "Logged on interactively."],
        ["S-1-5-6", "Service", "Logged on as a service."],
        ["S-1-5-7", "Anonymous", "Anonymous logon."],
        ["S-1-5-9", "Enterprise Domain Controllers", "All DCs in the forest."],
        ["S-1-5-11", "Authenticated Users", "Any authenticated identity."],
        ["S-1-5-18", "Local System (SYSTEM)", "The LocalSystem service account."],
        ["S-1-5-19", "Local Service", "The LocalService account."],
        ["S-1-5-20", "Network Service", "The NetworkService account."],
        ["S-1-5-32-544", "Administrators", "Built-in Administrators group."],
        ["S-1-5-32-545", "Users", "Built-in Users group."],
        ["S-1-5-32-546", "Guests", "Built-in Guests group."],
        ["S-1-5-32-551", "Backup Operators", "Can back up/restore files (privileged)."],
        ["S-1-5-32-555", "Remote Desktop Users", "Allowed to log on via RDP."],
      ];
      return refView(["SID", "Principal", "Meaning"], rows, v.q);
    } },

  { id: "id-sid-parse", name: "Windows SID String Parser", cat: "identity", desc: "Parse a textual Windows SID (S-R-I-S-S-...) into revision, identifier authority, sub-authorities and RID.", tags: ["windows", "sid", "rid", "parse", "ad"],
    inputs: [{ k: "sid", label: "SID", type: "text", placeholder: "S-1-5-21-3623811015-3361044348-30300820-1013" }],
    run(v) {
      const sid = S(v.sid).trim();
      if (!sid) return "";
      const m = sid.match(/^S-(\d+)-(\d+)((?:-\d+)*)$/i);
      if (!m) return { error: "Not a SID (expected S-1-5-...)." };
      const rev = m[1], auth = m[2];
      const subs = m[3] ? m[3].split("-").filter(Boolean) : [];
      const out = [["revision", rev], ["identifier authority", auth + (auth === "5" ? " (NT Authority)" : auth === "1" ? " (World)" : "")], ["sub-authorities", String(subs.length)]];
      subs.forEach((s, i) => out.push([`  sub-auth ${i + 1}`, s + (i === 0 && subs.length > 1 && s === "21" ? " (domain identifier follows)" : "")]));
      if (subs.length) out.push(["RID (last sub-auth)", subs[subs.length - 1]]);
      return table(out);
    } },

  { id: "id-sid-binary", name: "Windows Binary SID Decoder", cat: "identity", desc: "Decode a binary SID (hex, as stored in AD objectSid) into its S-R-I-... string form.", tags: ["windows", "sid", "objectsid", "binary", "hex"],
    inputs: [{ k: "hex", label: "Binary SID (hex)", type: "text", placeholder: "010200000000000520000000200200 00" }],
    run(v, H) {
      const h = S(v.hex).replace(/[^0-9a-fA-F]/g, "");
      if (!h) return "";
      if (h.length % 2) return { error: "Hex has an odd number of digits." };
      const b = H.fromHex(h);
      if (b.length < 8) return { error: "Too short for a SID (need at least 8 bytes)." };
      const rev = b[0];
      const count = b[1];
      let authority = 0;
      for (let i = 2; i < 8; i++) authority = authority * 256 + b[i]; // 48-bit big-endian
      if (b.length < 8 + count * 4) return { error: `Need ${8 + count * 4} bytes for ${count} sub-authorities, got ${b.length}.` };
      const subs = [];
      for (let i = 0; i < count; i++) {
        const o = 8 + i * 4;
        const val = (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0; // little-endian
        subs.push(val);
      }
      const sid = `S-${rev}-${authority}${subs.length ? "-" + subs.join("-") : ""}`;
      return `SID: ${sid}\n\nrevision:      ${rev}\nauthority:     ${authority}\nsub-auth count: ${count}${subs.length ? "\nRID:           " + subs[subs.length - 1] : ""}`;
    } },

  // ---------------- WebAuthn / FIDO2 / COSE ----------------
  { id: "id-webauthn-terms", name: "WebAuthn / FIDO2 Terminology", cat: "identity", desc: "Key WebAuthn and FIDO2 terms (passkeys, attestation, authenticator data, ...) explained.", tags: ["webauthn", "fido2", "passkey", "attestation", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "attestation, passkey" }],
    run(v) {
      const rows = [
        ["Relying Party (RP)", "The website/app the user authenticates to; identified by rpId."],
        ["Authenticator", "Hardware/software holding the private key (security key, phone, TPM)."],
        ["Passkey", "A discoverable (resident) WebAuthn credential, often synced."],
        ["Credential ID", "Identifier the RP uses to reference a stored credential."],
        ["clientDataJSON", "Challenge, origin and type, hashed and signed by the authenticator."],
        ["authenticatorData", "rpIdHash + flags + signCount + optional attested cred/extensions."],
        ["Attestation", "Registration ceremony; proves the authenticator's provenance."],
        ["Assertion", "Authentication ceremony; proves possession of the private key."],
        ["User Presence (UP)", "A simple touch/tap confirming a human is present."],
        ["User Verification (UV)", "Stronger check (PIN/biometric) of who the user is."],
        ["AAGUID", "128-bit identifier of the authenticator model."],
        ["CTAP", "Client to Authenticator Protocol (CTAP2 pairs with WebAuthn)."],
        ["Challenge", "Random value the RP issues to prevent replay."],
        ["COSE key", "Public key format (CBOR Object Signing and Encryption)."],
      ];
      return refView(["Term", "Meaning"], rows, v.q);
    } },

  { id: "id-cose-alg", name: "COSE Algorithm Reference", cat: "identity", desc: "COSE algorithm identifiers used by WebAuthn credentialPublicKey (alg values).", tags: ["cose", "webauthn", "es256", "rs256", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "-7, ES256" }],
    run(v) {
      const rows = [
        ["-7", "ES256", "ECDSA P-256 + SHA-256 (most common for passkeys)."],
        ["-35", "ES384", "ECDSA P-384 + SHA-384."],
        ["-36", "ES512", "ECDSA P-521 + SHA-512."],
        ["-8", "EdDSA", "Ed25519 / Ed448."],
        ["-47", "ES256K", "ECDSA secp256k1 + SHA-256."],
        ["-257", "RS256", "RSASSA-PKCS1-v1_5 + SHA-256 (legacy TPM/Windows Hello)."],
        ["-258", "RS384", "RSASSA-PKCS1-v1_5 + SHA-384."],
        ["-259", "RS512", "RSASSA-PKCS1-v1_5 + SHA-512."],
        ["-37", "PS256", "RSASSA-PSS + SHA-256."],
        ["-38", "PS384", "RSASSA-PSS + SHA-384."],
        ["-39", "PS512", "RSASSA-PSS + SHA-512."],
      ];
      return refView(["alg", "Name", "Meaning"], rows, v.q);
    } },

  { id: "id-authdata-flags", name: "WebAuthn Authenticator Data Flags", cat: "identity", desc: "Decode the WebAuthn authenticatorData flags byte (UP/UV/BE/BS/AT/ED). Accepts a single hex byte or full authData hex.", tags: ["webauthn", "fido2", "flags", "authenticatordata"],
    inputs: [{ k: "hex", label: "Flags byte or authData (hex)", type: "text", placeholder: "45" }],
    run(v, H) {
      const h = S(v.hex).replace(/[^0-9a-fA-F]/g, "");
      if (!h) return "";
      if (h.length % 2) return { error: "Hex has an odd number of digits." };
      const b = H.fromHex(h);
      let flags, src;
      if (b.length === 1) { flags = b[0]; src = "single byte"; }
      else if (b.length >= 37) { flags = b[32]; src = "byte 33 of authenticatorData (after 32-byte rpIdHash)"; }
      else return { error: "Give one flags byte, or full authenticatorData (>= 37 bytes)." };
      const defs = [
        [0x01, "UP", "User Present (a human touched the authenticator)"],
        [0x02, "RFU1", "reserved"],
        [0x04, "UV", "User Verified (PIN/biometric)"],
        [0x08, "BE", "Backup Eligible (credential may be synced)"],
        [0x10, "BS", "Backup State (credential is currently backed up/synced)"],
        [0x20, "RFU2", "reserved"],
        [0x40, "AT", "Attested credential data included"],
        [0x80, "ED", "Extension data included"],
      ];
      const out = defs.map(([bit, name, desc]) => [name, (flags & bit) ? "SET" : "-", desc]);
      return `flags byte: 0x${flags.toString(16).padStart(2, "0")} (${src})\n\n` + table([["flag", "state", "meaning"], ...out]);
    } },

  // ---------------- SSH ----------------
  { id: "id-ssh-pubkey", name: "SSH Public Key Parser & Fingerprint", cat: "identity", desc: "Parse an OpenSSH public key line (type base64 comment) and compute its SHA-256 fingerprint and key size.", tags: ["ssh", "pubkey", "fingerprint", "sha256", "authorized_keys"], button: "Parse",
    inputs: [{ k: "key", label: "SSH public key", type: "textarea", rows: 3, placeholder: "ssh-ed25519 AAAAC3Nza... user@host" }],
    async run(v) {
      const line = S(v.key).trim();
      if (!line) return "";
      const parts = line.split(/\s+/);
      if (parts.length < 2) return { error: "Expected: <type> <base64> [comment]." };
      const type = parts[0], b64 = parts[1], comment = parts.slice(2).join(" ");
      let blob;
      try { blob = b64bytes(b64); } catch (e) { return { error: "Key body is not valid Base64." }; }
      // read length-prefixed fields
      let p = 0;
      const field = () => { if (p + 4 > blob.length) return null; const n = (blob[p] << 24 | blob[p + 1] << 16 | blob[p + 2] << 8 | blob[p + 3]) >>> 0; p += 4; const d = blob.slice(p, p + n); p += n; return d; };
      const typeField = field();
      const embedded = typeField ? new TextDecoder().decode(typeField) : "";
      if (embedded && type !== embedded) return { error: `Type mismatch: label "${type}" vs embedded "${embedded}".` };
      let bits = "?";
      if (type === "ssh-rsa") { field(); const n = field(); if (n) bits = String(bitLen(n)); }
      else if (type === "ssh-ed25519") bits = "256";
      else if (/^ecdsa-sha2-nistp(\d+)/.test(type)) bits = type.match(/nistp(\d+)/)[1];
      else if (type === "ssh-dss") { const pp = field(); if (pp) bits = String(bitLen(pp)); }
      const dig = new Uint8Array(await crypto.subtle.digest("SHA-256", blob));
      let digBin = "";
      for (let i = 0; i < dig.length; i++) digBin += String.fromCharCode(dig[i]);
      const fp = "SHA256:" + btoa(digBin).replace(/=+$/, ""); // OpenSSH uses standard base64, no padding
      return table([
        ["type", type + (embedded ? "  (verified)" : "")],
        ["key size", bits + " bits"],
        ["fingerprint", fp],
        ["comment", comment || "(none)"],
        ["blob bytes", String(blob.length)],
      ]);
    } },

  { id: "id-authorized-keys", name: "authorized_keys Line Parser", cat: "identity", desc: "Parse an OpenSSH authorized_keys line, separating leading options (command=, from=, no-* restrictions) from the key.", tags: ["ssh", "authorized_keys", "options", "command", "restrict"],
    inputs: [{ k: "line", label: "authorized_keys line", type: "textarea", rows: 3, placeholder: 'command="/usr/bin/backup",no-pty ssh-ed25519 AAAA... key1' }],
    run(v) {
      let line = S(v.line).trim();
      if (!line) return "";
      if (line[0] === "#") return { error: "This is a comment line." };
      const keyTypes = /^(ssh-ed25519|ssh-rsa|ssh-dss|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp\d+@openssh\.com)$/;
      // options present only if the first token is not a key type
      let options = "";
      const firstTok = line.split(/\s+/)[0];
      if (!keyTypes.test(firstTok)) {
        // options string ends at the first whitespace that is not inside quotes
        let i = 0, inq = false;
        for (; i < line.length; i++) { const c = line[i]; if (c === '"') inq = !inq; else if (/\s/.test(c) && !inq) break; }
        options = line.slice(0, i); line = line.slice(i).trim();
      }
      const parts = line.split(/\s+/);
      if (parts.length < 2 || !keyTypes.test(parts[0])) return { error: "Could not find a valid key type after options." };
      const out = [];
      if (options) {
        // split options on commas not inside quotes
        const opts = []; let cur = "", inq = false;
        for (const c of options) { if (c === '"') { inq = !inq; cur += c; } else if (c === "," && !inq) { opts.push(cur); cur = ""; } else cur += c; }
        if (cur) opts.push(cur);
        out.push(["options", String(opts.length)]);
        opts.forEach((o, i) => out.push([`  opt ${i + 1}`, o]));
      } else out.push(["options", "(none - full access)"]);
      out.push(["key type", parts[0]]);
      out.push(["comment", parts.slice(2).join(" ") || "(none)"]);
      return table(out);
    } },

  // ---------------- Cookies / auth schemes ----------------
  { id: "id-cookie-prefix", name: "Cookie __Host- / __Secure- Checker", cat: "identity", desc: "Check whether a cookie's name and attributes satisfy the browser rules for the __Secure- and __Host- cookie prefixes.", tags: ["cookie", "__host", "__secure", "session", "prefix"],
    inputs: [
      { k: "name", label: "Cookie name", type: "text", placeholder: "__Host-session" },
      { k: "secure", label: "Secure attribute", type: "checkbox", value: true },
      { k: "path", label: "Path", type: "text", value: "/" },
      { k: "domain", label: "Domain attribute (blank = host-only)", type: "text", placeholder: "(leave blank for __Host-)" },
    ],
    run(v) {
      const name = S(v.name).trim();
      if (!name) return "";
      const out = [];
      if (name.startsWith("__Host-")) {
        const ok = [];
        ok.push(["Secure set", v.secure ? "PASS" : "FAIL - required"]);
        ok.push(["Path = /", v.path === "/" ? "PASS" : "FAIL - must be exactly /"]);
        ok.push(["No Domain", S(v.domain).trim() ? "FAIL - Domain must be omitted (host-only)" : "PASS"]);
        ok.push(["Served over HTTPS", "required (not checkable here)"]);
        const pass = v.secure && v.path === "/" && !S(v.domain).trim();
        return `Prefix: __Host-  (strictest - host-only, path=/)\n\n` + table(ok) + `\n\nResult: ${pass ? "valid __Host- cookie" : "INVALID - browsers will reject it"}`;
      }
      if (name.startsWith("__Secure-")) {
        const pass = !!v.secure;
        out.push(["Secure set", v.secure ? "PASS" : "FAIL - required"]);
        out.push(["Served over HTTPS", "required (not checkable here)"]);
        return `Prefix: __Secure-  (must be Secure, HTTPS)\n\n` + table(out) + `\n\nResult: ${pass ? "valid __Secure- cookie" : "INVALID - browsers will reject it"}`;
      }
      return `Name "${name}" uses no special prefix.\n\nUse __Host- for the strongest session cookies (Secure, Path=/, no Domain),\nor __Secure- to require the Secure flag.`;
    } },

  { id: "id-auth-schemes", name: "HTTP Authentication Scheme Reference", cat: "identity", desc: "HTTP Authorization / WWW-Authenticate schemes (Basic, Bearer, Digest, Negotiate, NTLM, SCRAM) and how they work.", tags: ["http auth", "authorization", "bearer", "negotiate", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "bearer, digest" }],
    run(v) {
      const rows = [
        ["Basic", "7617", "base64(user:pass) - MUST be over TLS; no hashing."],
        ["Bearer", "6750", "Opaque/JWT token: Authorization: Bearer <token>."],
        ["Digest", "7616", "Challenge-response with nonce; MD5/SHA-256, no cleartext."],
        ["Negotiate", "4559", "SPNEGO - wraps Kerberos or NTLM (Windows SSO)."],
        ["NTLM", "-", "Microsoft 3-message challenge-response handshake."],
        ["SCRAM-SHA-256", "7804", "Salted challenge-response; also a SASL mechanism."],
        ["HOBA", "7486", "HTTP Origin-Bound Auth using digital signatures."],
      ];
      return refView(["Scheme", "RFC", "How it works"], rows, v.q);
    } },

  // ---------------- SCIM ----------------
  { id: "id-scim-attrs", name: "SCIM 2.0 User Attribute Reference", cat: "identity", desc: "Core SCIM 2.0 User resource attributes used for cross-domain identity provisioning (RFC 7643).", tags: ["scim", "provisioning", "rfc7643", "user", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "userName, active" }],
    run(v) {
      const rows = [
        ["schemas", "URIs of the schemas the resource conforms to."],
        ["id", "Server-assigned unique identifier (read-only)."],
        ["externalId", "Identifier from the provisioning client's own system."],
        ["userName", "Unique login identifier (required)."],
        ["name", "Complex: formatted, familyName, givenName, ..."],
        ["displayName", "Name shown to users."],
        ["emails", "Multi-valued; each has value, type, primary."],
        ["phoneNumbers", "Multi-valued phone numbers."],
        ["active", "Boolean: whether the account is enabled."],
        ["password", "Write-only; sets the user's password."],
        ["groups", "Groups the user belongs to (usually read-only)."],
        ["roles", "Roles assigned to the user."],
        ["userType", "e.g. Employee, Contractor."],
        ["locale / timezone", "Localization preferences."],
        ["meta", "resourceType, created, lastModified, location, version."],
      ];
      return refView(["Attribute", "Meaning"], rows, v.q);
    } },

  // ---------------- SASL ----------------
  { id: "id-sasl-mechanisms", name: "SASL Mechanism Reference", cat: "identity", desc: "SASL authentication mechanisms (PLAIN, SCRAM, GSSAPI, OAUTHBEARER, ...) used by SMTP, IMAP, LDAP, XMPP and more.", tags: ["sasl", "scram", "gssapi", "oauthbearer", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "scram, oauth" }],
    run(v) {
      const rows = [
        ["PLAIN", "4616", "Sends authzid\\0authcid\\0password - needs TLS."],
        ["LOGIN", "-", "Non-standard; base64 user then password (legacy)."],
        ["CRAM-MD5", "2195", "HMAC-MD5 challenge-response (weak, legacy)."],
        ["DIGEST-MD5", "2831", "Obsolete; superseded by SCRAM."],
        ["SCRAM-SHA-1", "5802", "Salted challenge-response, mutual auth."],
        ["SCRAM-SHA-256", "7677", "SCRAM with SHA-256 (preferred)."],
        ["GSSAPI", "4752", "Kerberos v5 authentication."],
        ["EXTERNAL", "4422", "Auth from a lower layer, e.g. TLS client certificate."],
        ["ANONYMOUS", "4505", "Unauthenticated/guest access."],
        ["OAUTHBEARER", "7628", "OAuth 2.0 bearer tokens over SASL."],
        ["XOAUTH2", "-", "Google/Microsoft OAuth 2.0 SASL (pre-OAUTHBEARER)."],
      ];
      return refView(["Mechanism", "RFC", "Notes"], rows, v.q);
    } },

  // ---------------- Email identity / token formats ----------------
  { id: "id-email-normalize", name: "Email Address Normalizer", cat: "identity", desc: "Produce a canonical form of an email for account matching/dedup - lowercases, strips +tags, and applies Gmail dot rules. Heuristic, not for delivery.", tags: ["email", "normalize", "canonical", "gmail", "identity"],
    inputs: [
      { k: "email", label: "Email address", type: "text", placeholder: "John.Doe+news@Gmail.com" },
      { k: "stripplus", label: "Strip +tag", type: "checkbox", value: true },
    ],
    run(v) {
      const raw = S(v.email).trim();
      if (!raw) return "";
      const at = raw.lastIndexOf("@");
      if (at < 1 || at === raw.length - 1) return { error: "Not an email address (need local@domain)." };
      let local = raw.slice(0, at);
      let domain = raw.slice(at + 1).toLowerCase();
      const gmail = domain === "gmail.com" || domain === "googlemail.com";
      let localLc = local.toLowerCase();
      const notes = [];
      if (v.stripplus && localLc.includes("+")) { localLc = localLc.split("+")[0]; notes.push("removed +tag"); }
      if (gmail) {
        const before = localLc;
        localLc = localLc.replace(/\./g, "");
        if (before !== localLc) notes.push("removed Gmail dots");
        if (domain === "googlemail.com") { domain = "gmail.com"; notes.push("googlemail.com -> gmail.com"); }
      }
      return `original:  ${raw}\ncanonical: ${localLc}@${domain}\n\nnotes:     ${notes.length ? notes.join(", ") : "lowercased only"}\n(Heuristic for matching accounts - do NOT use as the delivery address.)`;
    } },

  { id: "id-token-prefix", name: "Credential Token Prefix Reference", cat: "identity", desc: "Identify secret tokens by their well-known prefixes (AWS, GitHub, Stripe, Slack, Google, ...). Useful for secret scanning.", tags: ["secret", "token", "api key", "prefix", "reference"],
    inputs: [{ k: "q", label: "Filter or paste a token", type: "text", placeholder: "ghp_ or AKIA..." }],
    run(v) {
      const rows = [
        ["AKIA", "AWS", "Access Key ID (long-term)."],
        ["ASIA", "AWS", "Access Key ID (temporary / STS)."],
        ["ghp_", "GitHub", "Personal access token (classic)."],
        ["gho_", "GitHub", "OAuth access token."],
        ["ghu_", "GitHub", "User-to-server token (GitHub App)."],
        ["ghs_", "GitHub", "Server-to-server token (GitHub App)."],
        ["ghr_", "GitHub", "Refresh token."],
        ["github_pat_", "GitHub", "Fine-grained personal access token."],
        ["glpat-", "GitLab", "Personal access token."],
        ["xoxb-", "Slack", "Bot user OAuth token."],
        ["xoxp-", "Slack", "User OAuth token."],
        ["sk_live_", "Stripe", "Secret key (live)."],
        ["pk_live_", "Stripe", "Publishable key (live)."],
        ["rk_live_", "Stripe", "Restricted key (live)."],
        ["AIza", "Google", "API key."],
        ["ya29.", "Google", "OAuth 2.0 access token."],
        ["SG.", "SendGrid", "API key."],
        ["npm_", "npm", "Access token."],
        ["dop_v1_", "DigitalOcean", "Personal access token."],
        ["shpat_", "Shopify", "Admin API access token."],
        ["eyJ", "JWT", "Base64url of {\" - a JSON Web Token header."],
      ];
      const q = S(v.q).trim();
      if (q) {
        const hit = rows.filter((r) => q.toLowerCase().startsWith(r[0].toLowerCase()) || r[0].toLowerCase().includes(q.toLowerCase()) || r[1].toLowerCase().includes(q.toLowerCase()));
        if (hit.length) return refView(["Prefix", "Service", "Meaning"], hit, "");
        return refView(["Prefix", "Service", "Meaning"], rows, q);
      }
      return refView(["Prefix", "Service", "Meaning"], rows, "");
    } },

  // ---------------- Active Directory time / GUID ----------------
  { id: "id-filetime", name: "Windows FILETIME Converter", cat: "identity", desc: "Convert a Windows FILETIME (100-ns intervals since 1601, used by AD pwdLastSet/lastLogon/accountExpires) to a UTC date, or back.", tags: ["filetime", "ad", "pwdlastset", "timestamp", "windows"],
    inputs: [
      { k: "value", label: "FILETIME (decimal/0x hex) or ISO date", type: "text", placeholder: "132539328000000000" },
      { k: "dir", label: "Direction", type: "select", opts: ["FILETIME -> date", "date -> FILETIME"], value: "FILETIME -> date" },
    ],
    run(v) {
      const raw = S(v.value).trim();
      if (!raw) return "";
      const EPOCH = 11644473600000n; // ms between 1601-01-01 and 1970-01-01
      if (v.dir === "date -> FILETIME") {
        const ms = Date.parse(raw);
        if (isNaN(ms)) return { error: "Could not parse date (try ISO 8601, e.g. 2021-01-01T00:00:00Z)." };
        const ft = (BigInt(ms) + EPOCH) * 10000n;
        return `date:     ${new Date(ms).toISOString()}\nFILETIME: ${ft.toString()}\nhex:      0x${ft.toString(16).toUpperCase()}`;
      }
      let ft;
      try { ft = BigInt(raw); } catch (e) { return { error: "FILETIME must be an integer (decimal or 0x hex)." }; }
      if (ft === 0n) return "FILETIME 0 = not set / never (1601-01-01T00:00:00Z).";
      if (ft === 9223372036854775807n) return "FILETIME 0x7FFFFFFFFFFFFFFF = 'never' (e.g. accountExpires = never).";
      const ms = ft / 10000n - EPOCH;
      const d = new Date(Number(ms));
      if (isNaN(d.getTime())) return { error: "FILETIME out of representable date range." };
      return `FILETIME: ${ft.toString()}\nUTC:      ${d.toISOString()}`;
    } },

  { id: "id-objectguid-decode", name: "AD objectGUID Decoder", cat: "identity", desc: "Decode a 16-byte Active Directory objectGUID (hex) into its canonical GUID string, applying AD's mixed byte order.", tags: ["ad", "objectguid", "guid", "binary", "hex"],
    inputs: [{ k: "hex", label: "objectGUID (hex, 16 bytes)", type: "text", placeholder: "d1 3c 2e 4b ... (32 hex digits)" }],
    run(v, H) {
      const h = S(v.hex).replace(/[^0-9a-fA-F]/g, "");
      if (!h) return "";
      if (h.length !== 32) return { error: `Need exactly 16 bytes (32 hex digits), got ${Math.floor(h.length / 2)} bytes.` };
      const b = H.fromHex(h);
      const x = (i) => b[i].toString(16).padStart(2, "0");
      const g = `${x(3)}${x(2)}${x(1)}${x(0)}-${x(5)}${x(4)}-${x(7)}${x(6)}-${x(8)}${x(9)}-${x(10)}${x(11)}${x(12)}${x(13)}${x(14)}${x(15)}`;
      return `GUID: ${g}\n\n(AD stores the first three groups little-endian and the last two big-endian.)`;
    } },

  { id: "id-ssh-keytypes", name: "SSH Key Algorithm Reference", cat: "identity", desc: "OpenSSH public key algorithm identifiers and what they mean.", tags: ["ssh", "key", "ed25519", "ecdsa", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "ed25519, fido" }],
    run(v) {
      const rows = [
        ["ssh-ed25519", "Ed25519 (EdDSA). Fast, small, recommended default."],
        ["ssh-rsa", "RSA. Still common; use 3072+ bit keys and SHA-2 signatures."],
        ["rsa-sha2-256 / -512", "RSA signatures using SHA-2 (modern replacement for ssh-rsa)."],
        ["ecdsa-sha2-nistp256", "ECDSA on NIST P-256."],
        ["ecdsa-sha2-nistp384", "ECDSA on NIST P-384."],
        ["ecdsa-sha2-nistp521", "ECDSA on NIST P-521."],
        ["ssh-dss", "DSA (1024-bit). Deprecated and disabled by default."],
        ["sk-ssh-ed25519@openssh.com", "FIDO/U2F security-key-backed Ed25519."],
        ["sk-ecdsa-sha2-nistp256@openssh.com", "FIDO/U2F security-key-backed ECDSA."],
        ["ssh-ed25519-cert-v01@openssh.com", "OpenSSH certificate wrapping an Ed25519 key."],
      ];
      return refView(["Algorithm", "Meaning"], rows, v.q);
    } },

  { id: "id-amr-values", name: "OIDC amr Value Reference", cat: "identity", desc: "Authentication Method Reference (amr) values for the OIDC amr claim (RFC 8176).", tags: ["oidc", "amr", "mfa", "rfc8176", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "mfa, otp" }],
    run(v) {
      const rows = [
        ["pwd", "Password or PIN-based authentication."],
        ["mfa", "Multiple-factor authentication was performed."],
        ["otp", "One-time password (e.g. TOTP/HOTP token)."],
        ["sms", "Confirmation by SMS message."],
        ["tel", "Confirmation by telephone call."],
        ["hwk", "Proof of possession of a hardware-secured key."],
        ["swk", "Proof of possession of a software-secured key."],
        ["sc", "Smart card."],
        ["pin", "Personal Identification Number."],
        ["fpt", "Fingerprint biometric."],
        ["face", "Facial recognition biometric."],
        ["iris", "Iris scan biometric."],
        ["geo", "Use of geolocation information."],
        ["kba", "Knowledge-based authentication (security questions)."],
        ["wia", "Windows Integrated Authentication."],
        ["user", "User presence test (e.g. a physical touch)."],
      ];
      return refView(["amr value", "Meaning"], rows, v.q);
    } },

  { id: "id-saml-nameid", name: "SAML NameID Format Reference", cat: "identity", desc: "SAML 2.0 NameID Format URIs and what kind of subject identifier each represents.", tags: ["saml", "nameid", "persistent", "transient", "reference"],
    inputs: [{ k: "q", label: "Filter", type: "text", placeholder: "persistent, email" }],
    run(v) {
      const rows = [
        ["...:1.1:nameid-format:emailAddress", "Identifier is an email address."],
        ["...:1.1:nameid-format:unspecified", "Format not specified; interpretation left to the parties."],
        ["...:1.1:nameid-format:X509SubjectName", "An X.509 certificate subject DN."],
        ["...:1.1:nameid-format:WindowsDomainQualifiedName", "DOMAIN\\user style name."],
        ["...:2.0:nameid-format:persistent", "Stable, privacy-preserving pseudonym per SP."],
        ["...:2.0:nameid-format:transient", "One-time, session-scoped identifier."],
        ["...:2.0:nameid-format:kerberos", "A Kerberos principal name."],
        ["...:2.0:nameid-format:entity", "Identifies a SAML entity (not a user)."],
      ];
      return refView(["NameID Format (urn:oasis:names:tc:SAML)", "Meaning"], rows, v.q);
    } },
];
