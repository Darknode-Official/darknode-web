// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Source-available for learning only. Redistribution prohibited. See LICENSE.
(function(){var _h=location.hostname,_a=["darknode.ai","www.darknode.ai","localhost","127.0.0.1"];if(!_a.some(function(d){return _h===d}))throw document.body.innerHTML="",new Error("unlicensed")}());

// ============================================================================
// DARKNODE CERT ANALYZER — TLS/SSL Certificate & Cipher Suite Toolkit
// PEM viewer, certificate field explainer, cipher suite reference,
// TLS version comparison, key size recommendations, SSL attack reference.
// ============================================================================

const CERT_FIELDS = {
  version: { name: "Version", desc: "X.509 certificate version. Almost always v3 (value 2). v1 lacks extensions." },
  serialNumber: { name: "Serial Number", desc: "Unique identifier assigned by the Certificate Authority. Must be unique per CA." },
  signatureAlgorithm: { name: "Signature Algorithm", desc: "Algorithm the CA used to sign this certificate (e.g., SHA-256 with RSA)." },
  issuer: { name: "Issuer", desc: "The Certificate Authority that issued (signed) this certificate." },
  validity: { name: "Validity Period", desc: "The window during which the certificate is valid (Not Before → Not After)." },
  subject: { name: "Subject", desc: "The entity this certificate identifies (domain, organization, etc.)." },
  subjectPublicKeyInfo: { name: "Subject Public Key", desc: "The public key of the certificate holder, including algorithm and key size." },
  extensions: { name: "Extensions", desc: "X.509v3 extensions: Subject Alternative Names, Key Usage, Basic Constraints, etc." },
  subjectAltName: { name: "Subject Alt Names", desc: "Additional domains/IPs this certificate covers. Browsers check SAN, not CN." },
  keyUsage: { name: "Key Usage", desc: "What the key may be used for: digitalSignature, keyEncipherment, etc." },
  extKeyUsage: { name: "Extended Key Usage", desc: "Application-specific purposes: serverAuth, clientAuth, codeSigning, etc." },
  basicConstraints: { name: "Basic Constraints", desc: "Whether this is a CA certificate and the maximum chain depth." },
  authorityKeyIdentifier: { name: "Authority Key ID", desc: "Identifies the CA's public key that signed this cert. Used for chain building." },
  subjectKeyIdentifier: { name: "Subject Key ID", desc: "Hash of this certificate's public key. Referenced by child certs' AKI." },
  crlDistributionPoints: { name: "CRL Distribution Points", desc: "URLs where the CA's Certificate Revocation List can be downloaded." },
  authorityInfoAccess: { name: "Authority Info Access", desc: "OCSP responder URL (for real-time revocation checking) and CA issuer URL." },
  certificatePolicies: { name: "Certificate Policies", desc: "OIDs indicating the policy under which the cert was issued (DV, OV, EV)." },
  sctList: { name: "SCT List", desc: "Signed Certificate Timestamps for Certificate Transparency compliance." },
};

const KEY_RECOMMENDATIONS = [
  { algo: "RSA", minBits: 2048, recommended: 3072, maxSecurity: 4096, status: "Current standard", note: "2048 minimum through 2030. NIST recommends 3072+ for new systems." },
  { algo: "ECDSA", minBits: 256, recommended: 384, maxSecurity: 521, status: "Preferred for performance", note: "P-256 (secp256r1) most common. P-384 for higher security." },
  { algo: "Ed25519", minBits: 256, recommended: 256, maxSecurity: 256, status: "Modern choice", note: "Fixed 256-bit. Faster than ECDSA, deterministic signatures." },
  { algo: "Ed448", minBits: 448, recommended: 448, maxSecurity: 448, status: "Highest EdDSA", note: "448-bit. ~224-bit security level. Limited support." },
  { algo: "DSA", minBits: 2048, recommended: 0, maxSecurity: 3072, status: "Deprecated", note: "Removed from modern TLS. Do not use for new deployments." },
  { algo: "RSA (legacy)", minBits: 1024, recommended: 0, maxSecurity: 1024, status: "Broken", note: "1024-bit RSA factored. All CAs stopped issuing in 2013." },
];

const CIPHER_SUITES = [
  { name:"TLS_AES_256_GCM_SHA384", tls:"1.3", kx:"—",auth:"—",enc:"AES-256-GCM",mac:"SHA-384",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_AES_128_GCM_SHA256", tls:"1.3", kx:"—",auth:"—",enc:"AES-128-GCM",mac:"SHA-256",bits:128,sec:"Recommended",pfs:true },
  { name:"TLS_CHACHA20_POLY1305_SHA256", tls:"1.3", kx:"—",auth:"—",enc:"ChaCha20-Poly1305",mac:"SHA-256",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", tls:"1.2", kx:"ECDHE",auth:"ECDSA",enc:"AES-256-GCM",mac:"SHA-384",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls:"1.2", kx:"ECDHE",auth:"RSA",enc:"AES-256-GCM",mac:"SHA-384",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls:"1.2", kx:"ECDHE",auth:"ECDSA",enc:"AES-128-GCM",mac:"SHA-256",bits:128,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls:"1.2", kx:"ECDHE",auth:"RSA",enc:"AES-128-GCM",mac:"SHA-256",bits:128,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", tls:"1.2", kx:"ECDHE",auth:"ECDSA",enc:"ChaCha20-Poly1305",mac:"SHA-256",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", tls:"1.2", kx:"ECDHE",auth:"RSA",enc:"ChaCha20-Poly1305",mac:"SHA-256",bits:256,sec:"Recommended",pfs:true },
  { name:"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", tls:"1.2", kx:"DHE",auth:"RSA",enc:"AES-256-GCM",mac:"SHA-384",bits:256,sec:"Secure",pfs:true },
  { name:"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", tls:"1.2", kx:"DHE",auth:"RSA",enc:"AES-128-GCM",mac:"SHA-256",bits:128,sec:"Secure",pfs:true },
  { name:"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", tls:"1.2", kx:"ECDHE",auth:"RSA",enc:"AES-256-CBC",mac:"SHA-384",bits:256,sec:"Acceptable",pfs:true },
  { name:"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", tls:"1.2", kx:"ECDHE",auth:"RSA",enc:"AES-128-CBC",mac:"SHA-256",bits:128,sec:"Acceptable",pfs:true },
  { name:"TLS_RSA_WITH_AES_256_GCM_SHA384", tls:"1.2", kx:"RSA",auth:"RSA",enc:"AES-256-GCM",mac:"SHA-384",bits:256,sec:"Weak (no PFS)",pfs:false },
  { name:"TLS_RSA_WITH_AES_128_GCM_SHA256", tls:"1.2", kx:"RSA",auth:"RSA",enc:"AES-128-GCM",mac:"SHA-256",bits:128,sec:"Weak (no PFS)",pfs:false },
  { name:"TLS_RSA_WITH_AES_256_CBC_SHA256", tls:"1.2", kx:"RSA",auth:"RSA",enc:"AES-256-CBC",mac:"SHA-256",bits:256,sec:"Weak",pfs:false },
  { name:"TLS_RSA_WITH_AES_128_CBC_SHA", tls:"1.0+", kx:"RSA",auth:"RSA",enc:"AES-128-CBC",mac:"SHA-1",bits:128,sec:"Legacy",pfs:false },
  { name:"TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls:"1.0+", kx:"RSA",auth:"RSA",enc:"3DES-CBC",mac:"SHA-1",bits:112,sec:"Insecure",pfs:false },
  { name:"TLS_RSA_WITH_RC4_128_SHA", tls:"1.0+", kx:"RSA",auth:"RSA",enc:"RC4",mac:"SHA-1",bits:128,sec:"Insecure",pfs:false },
  { name:"TLS_RSA_WITH_RC4_128_MD5", tls:"1.0+", kx:"RSA",auth:"RSA",enc:"RC4",mac:"MD5",bits:128,sec:"Insecure",pfs:false },
  { name:"TLS_RSA_WITH_NULL_SHA", tls:"1.0+", kx:"RSA",auth:"RSA",enc:"None",mac:"SHA-1",bits:0,sec:"No encryption",pfs:false },
  { name:"TLS_RSA_EXPORT_WITH_RC4_40_MD5", tls:"SSL 3.0", kx:"RSA_EXPORT",auth:"RSA",enc:"RC4-40",mac:"MD5",bits:40,sec:"Broken (export)",pfs:false },
  { name:"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA", tls:"SSL 3.0", kx:"RSA_EXPORT",auth:"RSA",enc:"DES-40-CBC",mac:"SHA-1",bits:40,sec:"Broken (export)",pfs:false },
];

const TLS_VERSIONS = [
  { ver:"SSL 2.0", year:1995, status:"Broken", rfc:"—", notes:"Vulnerable to downgrade, MAC flaws, no handshake protection. Prohibited by RFC 6176." },
  { ver:"SSL 3.0", year:1996, status:"Broken", rfc:"RFC 6101", notes:"POODLE attack (2014). Prohibited by RFC 7568." },
  { ver:"TLS 1.0", year:1999, status:"Deprecated", rfc:"RFC 2246", notes:"BEAST attack. PCI DSS prohibits. Deprecated by RFC 8996." },
  { ver:"TLS 1.1", year:2006, status:"Deprecated", rfc:"RFC 4346", notes:"No known critical vulnerabilities but lacks modern ciphers. Deprecated by RFC 8996." },
  { ver:"TLS 1.2", year:2008, status:"Current", rfc:"RFC 5246", notes:"Widely deployed. Supports AEAD ciphers. Still secure with good configuration." },
  { ver:"TLS 1.3", year:2018, status:"Recommended", rfc:"RFC 8446", notes:"Removed insecure features. 1-RTT handshake. Only AEAD ciphers. 0-RTT optional." },
];

const SSL_ATTACKS = [
  { name:"POODLE", year:2014, affects:"SSL 3.0, TLS 1.0 (CBC)", desc:"Padding Oracle On Downgraded Legacy Encryption. Decrypts individual bytes of CBC-encrypted traffic.", mitigation:"Disable SSL 3.0. Use TLS_FALLBACK_SCSV." },
  { name:"BEAST", year:2011, affects:"TLS 1.0 (CBC)", desc:"Browser Exploit Against SSL/TLS. Chosen-plaintext attack on CBC mode in TLS 1.0.", mitigation:"Use TLS 1.1+ or prefer RC4 (now also broken) or AEAD ciphers." },
  { name:"CRIME", year:2012, affects:"TLS compression", desc:"Compression Ratio Info-leak Made Easy. Uses compressed responses to leak session cookies.", mitigation:"Disable TLS-level compression." },
  { name:"BREACH", year:2013, affects:"HTTP compression", desc:"Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext. Targets HTTP compression.", mitigation:"Disable HTTP compression for sensitive pages, use CSRF tokens." },
  { name:"Heartbleed", year:2014, affects:"OpenSSL 1.0.1–1.0.1f", desc:"CVE-2014-0160. Buffer over-read in OpenSSL heartbeat extension. Leaks server memory including private keys.", mitigation:"Update OpenSSL. Revoke and reissue certificates." },
  { name:"FREAK", year:2015, affects:"Export cipher suites", desc:"Factoring RSA Export Keys. Man-in-the-middle forces export-grade RSA (512-bit), then factors it.", mitigation:"Disable export cipher suites." },
  { name:"Logjam", year:2015, affects:"DHE export suites", desc:"Downgrade to 512-bit DH. Precomputation makes common 1024-bit DH groups breakable.", mitigation:"Disable export suites. Use 2048+ bit DH parameters or ECDHE." },
  { name:"DROWN", year:2016, affects:"SSLv2 (cross-protocol)", desc:"Decrypting RSA with Obsolete and Weakened eNcryption. SSLv2 on same key lets attacker decrypt TLS sessions.", mitigation:"Disable SSLv2. Ensure no server shares a key with SSLv2-enabled server." },
  { name:"ROBOT", year:2017, affects:"RSA key exchange", desc:"Return Of Bleichenbacher's Oracle Threat. Bleichenbacher padding oracle on RSA key transport.", mitigation:"Disable RSA key exchange. Use ECDHE or DHE." },
  { name:"Lucky Thirteen", year:2013, affects:"TLS CBC mode", desc:"Timing side-channel on CBC MAC verification. Can recover plaintext.", mitigation:"Use AEAD ciphers (GCM, ChaCha20-Poly1305)." },
  { name:"Raccoon", year:2020, affects:"DH key exchange", desc:"Timing vulnerability in DH key exchange when leading zero bytes occur.", mitigation:"Use ECDHE instead of DHE. Update TLS libraries." },
  { name:"Sweet32", year:2016, affects:"3DES, Blowfish (64-bit blocks)", desc:"Birthday attack on 64-bit block ciphers. ~32 GB of data needed.", mitigation:"Disable 3DES and Blowfish. Use AES (128-bit blocks)." },
  { name:"Renegotiation Attack", year:2009, affects:"TLS renegotiation", desc:"Inject data into beginning of renegotiated TLS connection.", mitigation:"Implement RFC 5746 secure renegotiation indication." },
  { name:"GOLDENDOODLE", year:2019, affects:"TLS 1.2 CBC + 0-length padding", desc:"Variant of Zombie POODLE targeting specific implementations.", mitigation:"Use AEAD ciphers. Update TLS stack." },
];

const HSTS_REFERENCE = {
  purpose: "HTTP Strict Transport Security forces browsers to use HTTPS for all future requests to the domain.",
  header: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
  directives: [
    { name:"max-age", desc:"Time in seconds the browser should remember to only use HTTPS. 31536000 = 1 year." },
    { name:"includeSubDomains", desc:"Apply the HSTS policy to all subdomains as well." },
    { name:"preload", desc:"Request inclusion in browsers' built-in HSTS preload list. Requires max-age ≥ 1 year + includeSubDomains." },
  ],
  preloadRequirements: [
    "Serve a valid certificate",
    "Redirect HTTP to HTTPS on the same host",
    "Serve all subdomains over HTTPS",
    "Serve an HSTS header on the base domain with: max-age ≥ 31536000, includeSubDomains, preload",
  ],
  risks: [
    "If your HTTPS breaks, users cannot access the site at all (no HTTP fallback)",
    "preload list inclusion is essentially permanent — removal takes months",
    "All subdomains must support HTTPS if includeSubDomains is set",
  ],
};

const CERT_STYLES = `
  .ct-wrap { font-family: var(--mono, 'JetBrains Mono', monospace); color: var(--txt, #e0e6ed); max-width: 1100px; margin: 0 auto; padding: 24px; }
  .ct-title { font-family: var(--sans, 'Sora', system-ui, sans-serif); font-size: 1.75rem; font-weight: 700; margin-bottom: 8px; background: linear-gradient(135deg, #4caf50, #00d4ff); -webkit-background-clip: text; background-clip: text; color: transparent; }
  .ct-sub { color: var(--txt-2, #8899aa); font-size: 0.85rem; margin-bottom: 24px; font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .ct-tabs { display: flex; gap: 4px; border-bottom: 1px solid var(--border, #1a2233); margin-bottom: 20px; flex-wrap: wrap; }
  .ct-tab { padding: 8px 14px; cursor: pointer; font-size: 0.78rem; border: none; background: transparent; color: var(--txt-2, #8899aa); border-bottom: 2px solid transparent; transition: all 0.15s; font-family: inherit; }
  .ct-tab:hover { color: var(--txt, #e0e6ed); }
  .ct-tab.active { color: #4caf50; border-bottom-color: #4caf50; }
  .ct-panel { display: none; }
  .ct-panel.active { display: block; }
  .ct-card { background: var(--card, #0d1117); border: 1px solid var(--border, #1a2233); border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .ct-card h3 { font-size: 1rem; font-weight: 600; margin: 0 0 12px; color: var(--txt, #e0e6ed); font-family: var(--sans, 'Sora', system-ui, sans-serif); }
  .ct-label { display: block; font-size: 0.73rem; color: var(--txt-2, #8899aa); margin-bottom: 4px; text-transform: uppercase; letter-spacing: 0.05em; }
  .ct-textarea { width: 100%; box-sizing: border-box; padding: 10px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.82rem; outline: none; resize: vertical; min-height: 120px; }
  .ct-textarea:focus { border-color: #4caf50; }
  .ct-btn { padding: 8px 18px; border: none; border-radius: 6px; cursor: pointer; font-family: inherit; font-size: 0.8rem; font-weight: 600; background: linear-gradient(135deg, #4caf50, #2e7d32); color: #fff; transition: all 0.15s; }
  .ct-btn:hover { filter: brightness(1.15); }
  .ct-table { width: 100%; border-collapse: collapse; font-size: 0.78rem; }
  .ct-table th { text-align: left; padding: 8px 10px; background: #0a0e16; color: var(--txt-2, #8899aa); font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; position: sticky; top: 0; z-index: 1; }
  .ct-table td { padding: 8px 10px; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .ct-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.7rem; font-weight: 600; }
  .ct-badge-green { background: rgba(76,175,80,0.15); color: #4caf50; }
  .ct-badge-yellow { background: rgba(255,183,77,0.15); color: #ffb74d; }
  .ct-badge-red { background: rgba(244,67,54,0.15); color: #f44336; }
  .ct-badge-blue { background: rgba(0,212,255,0.15); color: #00d4ff; }
  .ct-badge-grey { background: rgba(150,150,150,0.15); color: #999; }
  .ct-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid rgba(26,34,51,0.3); }
  .ct-row-label { color: var(--txt-2, #8899aa); font-size: 0.8rem; }
  .ct-row-value { color: var(--txt, #e0e6ed); font-size: 0.85rem; font-weight: 500; }
  .ct-input { width: 100%; box-sizing: border-box; padding: 10px 12px; background: var(--input-bg, #161b22); border: 1px solid var(--border, #1a2233); border-radius: 6px; color: var(--txt, #e0e6ed); font-family: inherit; font-size: 0.85rem; outline: none; }
  .ct-input:focus { border-color: #4caf50; }
  .ct-search { margin-bottom: 12px; }
  .ct-info { font-size: 0.8rem; color: var(--txt-2, #8899aa); margin: 4px 0 12px; line-height: 1.5; }
  .ct-code { background: #0a0e16; border: 1px solid var(--border, #1a2233); border-radius: 6px; padding: 12px; font-size: 0.82rem; white-space: pre-wrap; word-break: break-all; user-select: all; }
  @media (max-width: 700px) { .ct-tabs { gap: 0; } .ct-tab { padding: 6px 8px; font-size: 0.7rem; } }
`;

export function renderCertAnalyzer(container) {
  const s = document.createElement("style"); s.textContent = CERT_STYLES; document.head.appendChild(s);
  container.innerHTML = `
    <div class="ct-wrap">
      <div class="ct-title">Cert Analyzer</div>
      <div class="ct-sub">TLS/SSL certificate analysis, cipher suite reference, and security guidance</div>
      <div class="ct-tabs">
        <button class="ct-tab active" data-p="pem">PEM Viewer</button>
        <button class="ct-tab" data-p="fields">Field Reference</button>
        <button class="ct-tab" data-p="keys">Key Sizes</button>
        <button class="ct-tab" data-p="ciphers">Cipher Suites</button>
        <button class="ct-tab" data-p="versions">TLS Versions</button>
        <button class="ct-tab" data-p="attacks">SSL Attacks</button>
        <button class="ct-tab" data-p="hsts">HSTS</button>
        <button class="ct-tab" data-p="csr">CSR Helper</button>
      </div>

      <div class="ct-panel active" id="ctp-pem">
        <div class="ct-card">
          <h3>PEM Certificate Viewer</h3>
          <div class="ct-info">Paste a PEM-encoded certificate to decode its fields. Decoding is done client-side — nothing is uploaded.</div>
          <label class="ct-label">PEM Certificate</label>
          <textarea class="ct-textarea" id="pem-input" placeholder="-----BEGIN CERTIFICATE-----
MIIBojCCAUigAwIBAgIUZ...
-----END CERTIFICATE-----"></textarea>
          <button class="ct-btn" id="pem-parse" style="margin-top:12px;">Parse Certificate</button>
          <div id="pem-output"></div>
        </div>
      </div>

      <div class="ct-panel" id="ctp-fields">
        <div class="ct-card">
          <h3>X.509 Certificate Field Reference</h3>
          <table class="ct-table"><thead><tr><th>Field</th><th>Description</th></tr></thead><tbody id="fields-tbody"></tbody></table>
        </div>
      </div>

      <div class="ct-panel" id="ctp-keys">
        <div class="ct-card">
          <h3>Key Size Recommendations</h3>
          <div class="ct-info">NIST SP 800-57 Part 1 and industry best practices for cryptographic key lengths.</div>
          <table class="ct-table"><thead><tr><th>Algorithm</th><th>Minimum</th><th>Recommended</th><th>Max Security</th><th>Status</th><th>Notes</th></tr></thead><tbody id="keys-tbody"></tbody></table>
        </div>
      </div>

      <div class="ct-panel" id="ctp-ciphers">
        <div class="ct-card">
          <h3>TLS Cipher Suite Reference</h3>
          <div class="ct-search"><input class="ct-input" id="cipher-search" placeholder="Search by name, TLS version, encryption, or security level..."></div>
          <div style="max-height:600px;overflow-y:auto;"><table class="ct-table"><thead><tr><th>Cipher Suite</th><th>TLS</th><th>Key Ex</th><th>Encryption</th><th>Bits</th><th>PFS</th><th>Security</th></tr></thead><tbody id="ciphers-tbody"></tbody></table></div>
        </div>
      </div>

      <div class="ct-panel" id="ctp-versions">
        <div class="ct-card">
          <h3>TLS/SSL Version History</h3>
          <table class="ct-table"><thead><tr><th>Version</th><th>Year</th><th>Status</th><th>RFC</th><th>Notes</th></tr></thead><tbody id="versions-tbody"></tbody></table>
        </div>
      </div>

      <div class="ct-panel" id="ctp-attacks">
        <div class="ct-card">
          <h3>SSL/TLS Attack Reference</h3>
          <div class="ct-search"><input class="ct-input" id="attack-search" placeholder="Search attacks..."></div>
          <table class="ct-table"><thead><tr><th>Attack</th><th>Year</th><th>Affects</th><th>Description</th><th>Mitigation</th></tr></thead><tbody id="attacks-tbody"></tbody></table>
        </div>
      </div>

      <div class="ct-panel" id="ctp-hsts">
        <div class="ct-card">
          <h3>HSTS Reference</h3>
          <div class="ct-info">${HSTS_REFERENCE.purpose}</div>
          <div class="ct-label">Recommended Header</div>
          <div class="ct-code">${HSTS_REFERENCE.header}</div>
          <h3 style="margin-top:20px;">Directives</h3>
          <table class="ct-table"><thead><tr><th>Directive</th><th>Description</th></tr></thead><tbody>
            ${HSTS_REFERENCE.directives.map(d => `<tr><td style="font-weight:600;color:#4caf50;">${d.name}</td><td>${d.desc}</td></tr>`).join("")}
          </tbody></table>
          <h3 style="margin-top:20px;">HSTS Preload Requirements</h3>
          <ul style="font-size:0.82rem;line-height:1.8;padding-left:20px;color:var(--txt,#e0e6ed);">
            ${HSTS_REFERENCE.preloadRequirements.map(r => `<li>${r}</li>`).join("")}
          </ul>
          <h3 style="margin-top:20px;">Risks</h3>
          <ul style="font-size:0.82rem;line-height:1.8;padding-left:20px;color:#ffb74d;">
            ${HSTS_REFERENCE.risks.map(r => `<li>${r}</li>`).join("")}
          </ul>
        </div>
      </div>

      <div class="ct-panel" id="ctp-csr">
        <div class="ct-card">
          <h3>CSR Generator Helper</h3>
          <div class="ct-info">Generate the OpenSSL commands to create a Certificate Signing Request.</div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div><label class="ct-label">Common Name (domain)</label><input class="ct-input" id="csr-cn" placeholder="example.com" value="darknode.ai"></div>
            <div><label class="ct-label">Organization</label><input class="ct-input" id="csr-o" placeholder="My Company"></div>
            <div><label class="ct-label">Country (2-letter)</label><input class="ct-input" id="csr-c" placeholder="US" maxlength="2"></div>
            <div><label class="ct-label">State</label><input class="ct-input" id="csr-st" placeholder="California"></div>
            <div><label class="ct-label">Key Algorithm</label><select class="ct-input" id="csr-algo"><option value="rsa">RSA (2048)</option><option value="rsa4096">RSA (4096)</option><option value="ecdsa">ECDSA (P-256)</option><option value="ecdsa384">ECDSA (P-384)</option><option value="ed25519">Ed25519</option></select></div>
            <div><label class="ct-label">SANs (comma-separated)</label><input class="ct-input" id="csr-san" placeholder="www.example.com, api.example.com"></div>
          </div>
          <button class="ct-btn" id="csr-gen" style="margin-top:16px;">Generate Commands</button>
          <div id="csr-output"></div>
        </div>
      </div>
    </div>`;

  // Tabs
  container.querySelectorAll(".ct-tab").forEach(t => t.addEventListener("click", () => {
    container.querySelectorAll(".ct-tab").forEach(x=>x.classList.remove("active"));
    container.querySelectorAll(".ct-panel").forEach(x=>x.classList.remove("active"));
    t.classList.add("active");
    container.querySelector("#ctp-"+t.dataset.p).classList.add("active");
  }));

  // Fields table
  const fb = container.querySelector("#fields-tbody");
  for (const [k,v] of Object.entries(CERT_FIELDS)) {
    fb.innerHTML += `<tr><td style="font-weight:600;color:#4caf50;white-space:nowrap;">${v.name}</td><td style="font-size:0.78rem;">${v.desc}</td></tr>`;
  }

  // Keys table
  const kb = container.querySelector("#keys-tbody");
  for (const k of KEY_RECOMMENDATIONS) {
    const badge = k.status.includes("Deprecated")||k.status.includes("Broken") ? "ct-badge-red" : k.status.includes("Preferred")||k.status.includes("Modern") ? "ct-badge-blue" : "ct-badge-green";
    kb.innerHTML += `<tr><td style="font-weight:600;">${k.algo}</td><td>${k.minBits}</td><td style="color:#4caf50;font-weight:600;">${k.recommended||"—"}</td><td>${k.maxSecurity}</td><td><span class="ct-badge ${badge}">${k.status}</span></td><td style="font-size:0.75rem;color:var(--txt-2,#8899aa);">${k.note}</td></tr>`;
  }

  // Ciphers
  function renderCiphers(filter) {
    const f = (filter||"").toLowerCase();
    const filtered = f ? CIPHER_SUITES.filter(c => c.name.toLowerCase().includes(f)||c.tls.includes(f)||c.enc.toLowerCase().includes(f)||c.sec.toLowerCase().includes(f)) : CIPHER_SUITES;
    const tb = container.querySelector("#ciphers-tbody");
    tb.innerHTML = filtered.map(c => {
      const badge = c.sec.includes("Recommended")?"ct-badge-green":c.sec.includes("Secure")||c.sec.includes("Acceptable")?"ct-badge-yellow":c.sec.includes("Insecure")||c.sec.includes("Broken")||c.sec.includes("No enc")?"ct-badge-red":"ct-badge-grey";
      return `<tr><td style="font-size:0.72rem;word-break:break-all;">${c.name}</td><td>${c.tls}</td><td>${c.kx}</td><td>${c.enc}</td><td>${c.bits}</td><td>${c.pfs?'<span class="ct-badge ct-badge-green">Yes</span>':'<span class="ct-badge ct-badge-red">No</span>'}</td><td><span class="ct-badge ${badge}">${c.sec}</span></td></tr>`;
    }).join("");
  }
  container.querySelector("#cipher-search").addEventListener("input", e => renderCiphers(e.target.value));
  renderCiphers();

  // TLS Versions
  const vb = container.querySelector("#versions-tbody");
  for (const v of TLS_VERSIONS) {
    const badge = v.status==="Recommended"?"ct-badge-green":v.status==="Current"?"ct-badge-blue":v.status==="Deprecated"?"ct-badge-yellow":"ct-badge-red";
    vb.innerHTML += `<tr><td style="font-weight:600;">${v.ver}</td><td>${v.year}</td><td><span class="ct-badge ${badge}">${v.status}</span></td><td style="font-size:0.75rem;">${v.rfc}</td><td style="font-size:0.75rem;">${v.notes}</td></tr>`;
  }

  // Attacks
  function renderAttacks(filter) {
    const f = (filter||"").toLowerCase();
    const filtered = f ? SSL_ATTACKS.filter(a => a.name.toLowerCase().includes(f)||a.affects.toLowerCase().includes(f)||a.desc.toLowerCase().includes(f)) : SSL_ATTACKS;
    container.querySelector("#attacks-tbody").innerHTML = filtered.map(a => `<tr><td style="font-weight:600;color:#f44336;white-space:nowrap;">${a.name}</td><td>${a.year}</td><td style="font-size:0.75rem;">${a.affects}</td><td style="font-size:0.75rem;">${a.desc}</td><td style="font-size:0.75rem;color:#4caf50;">${a.mitigation}</td></tr>`).join("");
  }
  container.querySelector("#attack-search").addEventListener("input", e => renderAttacks(e.target.value));
  renderAttacks();

  // PEM parse (basic — browser-side PEM decode)
  container.querySelector("#pem-parse").addEventListener("click", () => {
    const pem = container.querySelector("#pem-input").value.trim();
    const out = container.querySelector("#pem-output");
    if (!pem) { out.innerHTML = '<div style="color:#f44336;margin-top:12px;">Paste a PEM certificate</div>'; return; }
    const m = pem.match(/-----BEGIN ([A-Z ]+)-----\s*([\s\S]+?)\s*-----END \1-----/);
    if (!m) { out.innerHTML = '<div style="color:#f44336;margin-top:12px;">Invalid PEM format</div>'; return; }
    const type = m[1];
    const b64 = m[2].replace(/\s/g, "");
    let bytes;
    try { bytes = atob(b64); } catch(e) { out.innerHTML = '<div style="color:#f44336;margin-top:12px;">Invalid Base64</div>'; return; }
    const hex = Array.from(bytes).map((_,i) => bytes.charCodeAt(i).toString(16).padStart(2,"0")).join(" ");
    const size = bytes.length;
    out.innerHTML = `
      <div class="ct-card" style="margin-top:16px;">
        <div class="ct-row"><span class="ct-row-label">Type</span><span class="ct-row-value">${type}</span></div>
        <div class="ct-row"><span class="ct-row-label">Size</span><span class="ct-row-value">${size} bytes (${(size*8).toLocaleString()} bits)</span></div>
        <div class="ct-row"><span class="ct-row-label">Base64 length</span><span class="ct-row-value">${b64.length} characters</span></div>
        <div style="margin-top:12px;"><span class="ct-label">Raw hex (first 256 bytes)</span><div class="ct-code" style="font-size:0.72rem;max-height:200px;overflow-y:auto;">${hex.slice(0, 256*3)}</div></div>
      </div>`;
  });

  // CSR generator
  container.querySelector("#csr-gen").addEventListener("click", () => {
    const cn = container.querySelector("#csr-cn").value||"example.com";
    const o = container.querySelector("#csr-o").value||"";
    const c = container.querySelector("#csr-c").value||"";
    const st = container.querySelector("#csr-st").value||"";
    const algo = container.querySelector("#csr-algo").value;
    const san = container.querySelector("#csr-san").value;
    const out = container.querySelector("#csr-output");
    let subj = `/CN=${cn}`;
    if (o) subj += `/O=${o}`;
    if (c) subj += `/C=${c.toUpperCase()}`;
    if (st) subj += `/ST=${st}`;
    let keyCmd, csrCmd, keyFile = cn.replace(/\./g,"_");
    switch(algo) {
      case "rsa": keyCmd = `openssl genrsa -out ${keyFile}.key 2048`; csrCmd = `openssl req -new -key ${keyFile}.key -out ${keyFile}.csr -subj "${subj}"`; break;
      case "rsa4096": keyCmd = `openssl genrsa -out ${keyFile}.key 4096`; csrCmd = `openssl req -new -key ${keyFile}.key -out ${keyFile}.csr -subj "${subj}"`; break;
      case "ecdsa": keyCmd = `openssl ecparam -genkey -name prime256v1 -out ${keyFile}.key`; csrCmd = `openssl req -new -key ${keyFile}.key -out ${keyFile}.csr -subj "${subj}"`; break;
      case "ecdsa384": keyCmd = `openssl ecparam -genkey -name secp384r1 -out ${keyFile}.key`; csrCmd = `openssl req -new -key ${keyFile}.key -out ${keyFile}.csr -subj "${subj}"`; break;
      case "ed25519": keyCmd = `openssl genpkey -algorithm Ed25519 -out ${keyFile}.key`; csrCmd = `openssl req -new -key ${keyFile}.key -out ${keyFile}.csr -subj "${subj}"`; break;
    }
    let sanExt = "";
    if (san) {
      const sans = san.split(",").map(s=>s.trim()).filter(Boolean);
      const sanStr = sans.map((s,i) => `DNS.${i+2}=${s}`).join(",");
      sanExt = ` \\\n  -addext "subjectAltName=DNS.1=${cn},${sanStr}"`;
    } else {
      sanExt = ` \\\n  -addext "subjectAltName=DNS=${cn}"`;
    }
    out.innerHTML = `
      <div class="ct-card" style="margin-top:16px;">
        <h3>Step 1: Generate Private Key</h3>
        <div class="ct-code">${keyCmd}</div>
        <h3 style="margin-top:16px;">Step 2: Generate CSR</h3>
        <div class="ct-code">${csrCmd}${sanExt}</div>
        <h3 style="margin-top:16px;">Step 3: Verify CSR</h3>
        <div class="ct-code">openssl req -text -noout -verify -in ${keyFile}.csr</div>
        <h3 style="margin-top:16px;">Step 4: Self-sign (testing only)</h3>
        <div class="ct-code">openssl x509 -req -days 365 -in ${keyFile}.csr -signkey ${keyFile}.key -out ${keyFile}.crt</div>
      </div>`;
  });
}
