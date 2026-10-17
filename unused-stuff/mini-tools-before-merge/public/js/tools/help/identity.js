// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved. See LICENSE.
// Plain-English help for the identity.js mini-tools. See help/README.md for the contract.
// Identity & Access: authentication, tokens and identity formats. Authorized use only.
export const HELP = {
  "id-pkce": {
    what: "Takes an OAuth PKCE code_verifier (or makes a random one) and works out the matching code_challenge that you send in the authorization request.",
    when: "You are building an OAuth 2.0 login for a mobile or single-page app and need the PKCE pair that protects the authorization code from interception.",
    example: { verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", method: "S256" },
  },
  "id-oauth-authz-url": {
    what: "Builds the full OAuth 2.0 / OpenID Connect authorization URL from the endpoint, client_id, scopes and other parameters you supply, URL-encoding each value.",
    when: "You are testing or documenting an OAuth login and want a ready-to-open authorize URL instead of assembling the query string by hand.",
    example: { endpoint: "https://issuer.example.com/authorize", client_id: "s6BhdRkqt3", redirect_uri: "https://app.example.com/callback", response_type: "code", scope: "openid profile email", state: "xyz123" },
  },
  "id-oauth-grants": {
    what: "Looks up OAuth 2.0 grant_type values and tells you which login flow each one drives and when to use it.",
    when: "You are choosing how an app should get tokens and want to pick the right OAuth flow for a web app, machine client or device.",
    example: { q: "device" },
  },
  "id-oauth-response-types": {
    what: "Explains the OAuth 2.0 / OIDC response_type values (code, token, id_token and their combinations) and which flow each selects.",
    when: "You are reading or writing an authorization request and need to know what a given response_type actually returns.",
    example: { q: "code" },
  },
  "id-oauth-errors": {
    what: "Looks up an OAuth 2.0, Bearer-token or device-flow error code and explains what the authorization server is telling you.",
    when: "You got an error like invalid_grant back from a token endpoint and want to know what went wrong.",
    example: { q: "invalid_grant" },
  },
  "id-oauth-device": {
    what: "Lists the fields and steps of the OAuth 2.0 Device Authorization Grant, such as user_code and verification_uri, and what each is for.",
    when: "You are implementing login on a TV, CLI or other device without a browser and need to understand the device flow.",
    example: { q: "user_code" },
  },
  "id-oidc-claims": {
    what: "Looks up OpenID Connect standard claims (both profile/email data and ID-token claims like sub and nonce) and explains each.",
    when: "You are reading an ID token or userinfo response and want to know what a claim name means.",
    example: { q: "email" },
  },
  "id-oidc-scopes": {
    what: "Shows each OpenID Connect scope and which user claims it releases when you request it.",
    when: "You are deciding which scopes your app should ask for and want to know what data each scope returns.",
    example: { q: "profile" },
  },
  "id-oidc-discovery": {
    what: "Explains the fields in an OpenID Provider's discovery document at /.well-known/openid-configuration.",
    when: "You are integrating with an identity provider and want to understand its discovery metadata, such as jwks_uri or the endpoints.",
    example: { q: "jwks" },
  },
  "id-token-introspect": {
    what: "Lists the fields of an OAuth 2.0 token introspection response (RFC 7662) and what each means, starting with active.",
    when: "You run a resource server that checks tokens via an introspection endpoint and need to read the response.",
    example: { q: "active" },
  },
  "id-jwt-claims": {
    what: "Looks up the registered JWT claim names (iss, sub, aud, exp and friends) and explains what each one carries.",
    when: "You are inspecting a JSON Web Token and want to understand the short claim names inside it.",
    example: { q: "exp" },
  },
  "id-jwt-headers": {
    what: "Explains the JOSE header parameters of a JWT/JWS/JWE, such as alg, kid, jku and x5c, including the risky ones.",
    when: "You are reviewing or hardening token handling and want to know what a header parameter does.",
    example: { q: "kid" },
  },
  "id-jwt-alg": {
    what: "Lists the signing algorithms a JWT can use (HS256, RS256, ES256, EdDSA, none) with the key type and security notes.",
    when: "You are choosing a JWT signing algorithm or checking one in a token and want to know what it implies.",
    example: { q: "ES256" },
  },
  "id-jwk-fields": {
    what: "Explains the members of a JSON Web Key for RSA, EC, OKP and symmetric keys, and flags which ones are private.",
    when: "You are reading a JWKS (the public keys an issuer publishes) and want to know what each field is.",
    example: { q: "kty" },
  },
  "id-hotp": {
    what: "Computes a counter-based one-time password (HOTP) from a Base32 secret and a counter value, following RFC 4226.",
    when: "You are testing or debugging a hardware/event-based OTP token and need to reproduce the code it would show.",
    example: { secret: "GEZDGNBVGY3TQOJQ", counter: "0", digits: "6", algo: "SHA-1" },
  },
  "id-otpauth-parse": {
    what: "Reads an otpauth:// URI (the text encoded in a 2FA QR code) and breaks out the issuer, account, secret and settings.",
    when: "You scanned or exported a 2FA setup QR code and want to see the secret and parameters it contains.",
    example: { uri: "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&period=30" },
  },
  "id-base32-secret": {
    what: "Checks that a 2FA secret is valid Base32, groups it into readable chunks and shows how many key bytes it decodes to.",
    when: "You are entering a TOTP secret by hand and want to confirm it is valid and strong enough.",
    example: { secret: "JBSWY3DPEHPK3PXP", group: "4" },
  },
  "id-totp-window": {
    what: "For a Unix time it computes the TOTP time-step counter, the counter in hex, and the start/end of the current 30-second window. No secret is used.",
    when: "You are debugging why two systems disagree on a TOTP code and want to compare their time windows.",
    example: { time: "1111111109", period: "30", t0: "0" },
  },
  "id-saml-decode": {
    what: "Decodes a SAMLRequest or SAMLResponse value: Base64 for the POST binding, or URL-encoded Base64 plus DEFLATE compression for the Redirect binding, then lays out the XML.",
    when: "You captured a SAML single sign-on message in a browser and want to read the XML inside it.",
    example: { data: "PHNhbWxwOlJlc3BvbnNlPjxzYW1sOklzc3Vlcj5odHRwczovL2lkcC5leGFtcGxlLmNvbTwvc2FtbDpJc3N1ZXI+PC9zYW1scDpSZXNwb25zZT4=", mode: "HTTP-POST (base64 only)" },
  },
  "id-saml-ref": {
    what: "Explains the main SAML 2.0 elements, such as Assertion, Subject and Conditions, and what each carries.",
    when: "You are reading a decoded SAML message and want to know what an element does.",
    example: { q: "Assertion" },
  },
  "id-saml-bindings": {
    what: "Lists the SAML 2.0 bindings (HTTP-Redirect, HTTP-POST, Artifact and more) with their URIs and how each moves the message.",
    when: "You are configuring single sign-on and need to know how a given binding transports the SAML message.",
    example: { q: "Redirect" },
  },
  "id-phc-parse": {
    what: "Parses a modern password hash in PHC format (Argon2, scrypt, PBKDF2) and shows the algorithm, cost parameters, salt and digest. It does not check any password.",
    when: "You are reviewing how an app stores passwords and want to read the cost settings in a stored hash.",
    example: { hash: "$argon2id$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG" },
  },
  "id-crypt-scheme": {
    what: "Looks at the prefix of a Unix crypt / shadow password hash and tells you which hashing scheme it uses (md5crypt, bcrypt, sha512crypt, yescrypt, ...).",
    when: "You found a password hash in /etc/shadow or a config and want to know how it was hashed.",
    example: { hash: "$6$rounds=5000$abcdefgh$0123456789" },
  },
  "id-shadow-parse": {
    what: "Splits an /etc/shadow line into its fields, turns the day-count columns into dates and tells you whether the account is locked.",
    when: "You are auditing Linux accounts and want to read the password-aging and lock state of an entry.",
    example: { line: "alice:$6$salt$hashvalue:19000:0:99999:7:::" },
  },
  "id-passwd-parse": {
    what: "Splits an /etc/passwd line into its fields and flags the account type from the UID and whether the shell allows login.",
    when: "You are reviewing a Linux host's accounts and want to spot system accounts or logins that should be disabled.",
    example: { line: "alice:x:1000:1000:Alice Example,,,:/home/alice:/bin/bash" },
  },
  "id-htpasswd-parse": {
    what: "Splits an Apache htpasswd line into the user and hash and identifies the hashing scheme (bcrypt, apr1, SHA-1, crypt). It does not verify the password.",
    when: "You are reviewing a Basic Auth htpasswd file and want to know how strong its stored hashes are.",
    example: { line: "admin:$apr1$abcdefgh$0123456789abcdefghij01" },
  },
  "id-digest-auth": {
    what: "Computes the HTTP Digest Access Authentication response hash and the full Authorization header from the username, password, nonce and request details.",
    when: "You are testing or debugging an endpoint that uses HTTP Digest authentication and need to craft a valid response.",
    example: { username: "Mufasa", password: "Circle Of Life", realm: "testrealm@host.com", method: "GET", uri: "/dir/index.html", nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093", qop: "auth", nc: "00000001", cnonce: "0a4f113b" },
  },
  "id-keyspace": {
    what: "Estimates how many possible passwords a policy allows, the entropy in bits, and the average time to crack it offline at a given guess rate.",
    when: "You are setting a password policy and want to show how length and character sets change the time to brute-force it. It measures the policy, not a specific password's guessability.",
    example: { length: "12", lower: true, upper: true, digits: true, symbols: false, rate: "1e9" },
  },
  "id-kerberos-etype": {
    what: "Looks up Kerberos encryption type (etype) numbers and tells you the algorithm and whether it is weak or roasting-friendly.",
    when: "You see an etype number in Kerberos traffic or a ticket and want to know what it means for security.",
    example: { q: "aes" },
  },
  "id-kerberos-spn": {
    what: "Breaks a Kerberos Service Principal Name (serviceclass/host:port/name) into its parts and lists common service classes.",
    when: "You are working with Active Directory service accounts or Kerberoasting and want to read an SPN.",
    example: { spn: "MSSQLSvc/db01.example.com:1433" },
  },
  "id-kerberos-flags": {
    what: "Looks up Kerberos ticket flags (forwardable, renewable, ok-as-delegate and others) and explains each, including delegation flags.",
    when: "You are analysing a Kerberos ticket and want to understand what its flags permit.",
    example: { q: "forwardable" },
  },
  "id-kerberos-errors": {
    what: "Looks up common Kerberos KDC and AP error codes and explains what each indicates, such as pre-auth required or clock skew.",
    when: "You hit a Kerberos authentication error and want to know its cause.",
    example: { q: "preauth" },
  },
  "id-ldap-dn-parse": {
    what: "Splits an LDAP Distinguished Name into its components, handling escaped characters and multi-valued RDNs.",
    when: "You are reading a long DN from a directory or certificate and want it broken into readable parts.",
    example: { dn: "CN=John Doe,OU=Users,DC=example,DC=com" },
  },
  "id-ldap-dn-escape": {
    what: "Escapes a value so it can be placed safely inside an LDAP Distinguished Name, covering special characters and leading/trailing spaces.",
    when: "You are building a DN from user-supplied text, for example a name that contains a comma.",
    example: { value: "Doe, John" },
  },
  "id-ldap-filter-escape": {
    what: "Escapes a value for use in an LDAP search filter, turning characters like parentheses and asterisks into their safe escape codes.",
    when: "You are building an LDAP query from untrusted input and need to prevent LDAP injection.",
    example: { value: "a*(b)c" },
  },
  "id-ldap-attrs": {
    what: "Looks up common LDAP and Active Directory attribute names (cn, sAMAccountName, objectSid and more) and explains what each holds.",
    when: "You are reading directory data and want to know what an attribute name means.",
    example: { q: "sam" },
  },
  "id-ad-uac": {
    what: "Decodes an Active Directory userAccountControl number into its individual flags and highlights the security-relevant ones.",
    when: "You see a userAccountControl value like 66048 on an account and want to know what settings it represents.",
    example: { value: "66048" },
  },
  "id-upn-parse": {
    what: "Parses a Windows logon name in either UPN (user@domain) or down-level (DOMAIN\\user) form and shows its parts.",
    when: "You are working with Windows accounts and want to separate the user and domain portions of a name.",
    example: { name: "alice@example.com" },
  },
  "id-well-known-rid": {
    what: "Looks up well-known Active Directory RIDs (the last number of a SID) such as 500 for Administrator or 512 for Domain Admins.",
    when: "You see a RID on a domain SID and want to know which built-in account or group it is.",
    example: { q: "krbtgt" },
  },
  "id-well-known-sid": {
    what: "Looks up well-known Windows SIDs such as S-1-5-18 (Local System) or S-1-1-0 (Everyone) and explains each.",
    when: "You see a SID in an access-control list or log and want to know which principal it represents.",
    example: { q: "system" },
  },
  "id-sid-parse": {
    what: "Parses a text Windows SID (S-1-5-...) into its revision, authority, sub-authorities and the trailing RID.",
    when: "You have a SID string and want to break it into its parts, for example to read the domain and RID.",
    example: { sid: "S-1-5-21-3623811015-3361044348-30300820-1013" },
  },
  "id-sid-binary": {
    what: "Decodes a binary SID in hex (as Active Directory stores objectSid) into its readable S-1-5-... string form.",
    when: "You pulled an objectSid as raw bytes from LDAP and need the normal SID string.",
    example: { hex: "010200000000000520000000 20020000" },
  },
  "id-webauthn-terms": {
    what: "Explains the key WebAuthn and FIDO2 terms, such as attestation, assertion, passkey and authenticator data.",
    when: "You are learning or implementing passwordless login with passkeys and want the vocabulary explained.",
    example: { q: "attestation" },
  },
  "id-cose-alg": {
    what: "Looks up the COSE algorithm numbers used in WebAuthn public keys (like -7 for ES256) and gives the name and meaning.",
    when: "You are reading a WebAuthn credential's public key and see an alg number you need to identify.",
    example: { q: "ES256" },
  },
  "id-authdata-flags": {
    what: "Decodes the WebAuthn authenticator-data flags byte, showing whether user presence, user verification, attestation and other bits are set.",
    when: "You are debugging a WebAuthn registration or login and want to read the flags byte in authenticatorData.",
    example: { hex: "45" },
  },
  "id-ssh-pubkey": {
    what: "Reads an OpenSSH public key line and reports its type, key size, SHA-256 fingerprint and comment. The fingerprint matches ssh-keygen -l.",
    when: "You want to confirm the fingerprint of a public key before trusting it, or see what type and size it is.",
    example: { key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPxW3J1JdMmOLCAXrbQRQodGeaCa6zu8rbAd0+z/VzQU alice@example.com" },
  },
  "id-authorized-keys": {
    what: "Parses an OpenSSH authorized_keys line, separating any leading options (such as command= or no-pty) from the key type and comment.",
    when: "You are reviewing an authorized_keys file and want to see what restrictions apply to a key.",
    example: { line: 'command="/usr/bin/backup",no-pty,no-port-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINDhVIrYQJj2Q9jWApR3l0kZvXYQY0oQ5X8Z7wq0r1a backup-key' },
  },
  "id-cookie-prefix": {
    what: "Checks whether a cookie's name and attributes meet the browser rules for the __Secure- and __Host- prefixes, which harden session cookies.",
    when: "You are naming a session cookie and want to be sure a __Host- or __Secure- prefixed cookie will not be rejected.",
    example: { name: "__Host-session", secure: true, path: "/", domain: "" },
  },
  "id-auth-schemes": {
    what: "Looks up HTTP authentication schemes (Basic, Bearer, Digest, Negotiate, NTLM, SCRAM) and explains how each works.",
    when: "You see a WWW-Authenticate or Authorization scheme name and want to know what it means.",
    example: { q: "bearer" },
  },
  "id-scim-attrs": {
    what: "Lists the core SCIM 2.0 User attributes used to provision accounts between systems and explains each.",
    when: "You are integrating SCIM user provisioning and want to know what an attribute like active or userName is for.",
    example: { q: "userName" },
  },
  "id-sasl-mechanisms": {
    what: "Looks up SASL authentication mechanisms (PLAIN, SCRAM, GSSAPI, OAUTHBEARER and more) used by mail, LDAP and chat protocols.",
    when: "You are configuring SMTP, IMAP, LDAP or XMPP authentication and want to know what a mechanism offers.",
    example: { q: "scram" },
  },
  "id-email-normalize": {
    what: "Produces a canonical version of an email address for matching accounts: it lowercases, removes a +tag, and applies Gmail's dot rules. It is a matching aid, not a delivery address.",
    when: "You are de-duplicating user accounts and want a single canonical form for addresses that reach the same inbox.",
    example: { email: "John.Doe+news@Gmail.com", stripplus: true },
  },
  "id-token-prefix": {
    what: "Identifies secret tokens and API keys by their well-known prefixes, such as ghp_ for GitHub or AKIA for AWS.",
    when: "You found a suspicious string in code or logs and want to know which service's credential it might be.",
    example: { q: "ghp_" },
  },
  "id-filetime": {
    what: "Converts a Windows FILETIME number (used by Active Directory for pwdLastSet and similar) into a UTC date, or a date back into a FILETIME.",
    when: "You pulled a timestamp like pwdLastSet from AD and need it as a human-readable date.",
    example: { value: "132539328000000000", dir: "FILETIME -> date" },
  },
  "id-objectguid-decode": {
    what: "Decodes a 16-byte Active Directory objectGUID in hex into its normal GUID string, applying AD's mixed byte order.",
    when: "You read an objectGUID as raw bytes from LDAP and want the GUID in its usual dashed form.",
    example: { hex: "d134bacd9f0a3f4e8b6a5c4d3e2f1a0b" },
  },
  "id-ssh-keytypes": {
    what: "Looks up OpenSSH public key algorithm names (ssh-ed25519, ssh-rsa, ecdsa-sha2-* and FIDO types) and explains each.",
    when: "You see a key type at the start of a public key and want to know what it is and whether to prefer it.",
    example: { q: "ed25519" },
  },
  "id-amr-values": {
    what: "Looks up the OpenID Connect amr (Authentication Methods References) values, such as pwd, otp and mfa, and explains each.",
    when: "You see an amr claim in an ID token and want to know which authentication methods were used.",
    example: { q: "mfa" },
  },
  "id-saml-nameid": {
    what: "Looks up the SAML 2.0 NameID Format URIs (persistent, transient, emailAddress and others) and explains what kind of identifier each is.",
    when: "You are configuring SAML single sign-on and need to pick or understand a NameID format.",
    example: { q: "persistent" },
  },
};
