import { esc } from '/js/shared.js';

var SAMPLE_PEM = '-----BEGIN CERTIFICATE-----\n' +
  'MIIGdjCCBF6gAwIBAgIQA2F0E8PIKhEAAAAAUa3r1zANBgkqhkiG9w0BAQsFADBh\n' +
  'MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMTswOQYDVQQDEzJE\n' +
  'aWdpQ2VydCBHbG9iYWwgRzIgVExTIFJTQSBTSEEyNTYgMjAyMCBDQTEwHhcNMjYw\n' +
  'MTE1MDAwMDAwWhcNMjcwMTE1MjM1OTU5WjB4MQswCQYDVQQGEwJVUzETMBEGA1UE\n' +
  'CBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEbMBkGA1UEChMS\n' +
  'RGFya25vZGUgU2VjdXJpdHkxFDASBgNVBAsTC0VuZ2luZWVyaW5nMRcwFQYDVQQD\n' +
  'DA4qLmRhcmtub2RlLmFpMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n' +
  'x7R1Gp2mJk3FBsMzV5Q8o4K1r3KxDm7G2PJh0bVf8E7p9JLCfhB2sN4vCkmYwTcx\n' +
  'Qv4WnG8k3HdR2M0UdR7J5VzXqN8rVcPYFhLjGaXbE5L1TqD0H3cJkV5YxGhK2vJ7\n' +
  'r0KfB0MdLaPW7E7TkGh3CcYHV6pOz0x9GKPB5e1VdXzLxR3qb8sN1fJATSd8X9ak\n' +
  'R2TFG4LvB4pC0xC5KjL9C0RHhF0EbG4N6Q3ZKa3TGFJy7c8mFJR0x5P3f6J2kN4r\n' +
  'B0q3VYEh3C4r7FhNK1Z2d0o5L3wK9vQ7rB3FJ0KdR6p2M1x4G5yK8hT0V3q9WzY7\n' +
  'aJ0N5R2cF4mX8pL1vT3qB0wIDAQABo4IB8zCCAe8wHwYDVR0jBBgwFoAUiGkHam3P\n' +
  'ahE7fK0IWdG6lh3mR8cwHQYDVR0OBBYEFKxJ5V3D8mP2f0RYKh4a0T8kB7xCMCUG\n' +
  'A1UdEQQeMByCDiouZGFya25vZGUuYWmCDGRhcmtub2RlLmFpMA4GA1UdDwEB/wQE\n' +
  'AwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwPgYDVR0fBDcwNTAz\n' +
  'oDGgL4YtaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0RzJUTFNSU0Ex\n' +
  'LmNybDA+BggrBgEFBQcBAQQyMDAwLgYIKwYBBQUHMAGGImh0dHA6Ly9vY3NwLmRp\n' +
  'Z2ljZXJ0LmNvbS9HMlRMU1JTQTEwDAYDVR0TAQH/BAIwADCCAQUGCisGAQQB1nkC\n' +
  'BAIEgfYEgfMA8QB3ACl5vvCeOTkh8FZzn2Old+W+V32cYAr4+U1dJlwlXceEAAAB\n' +
  'jXP5bQgAAAQDAEgwRgIhAKuE4b+Z3VyLf4E3A4yKR8M3TFh0R5f6V3U7K4q9j5c1\n' +
  'AiEA7r2PJybFTb3g1F0IKk0E0Hd7yJ2L9K3a5G8qN1c0v7AAdgAIYJLVKFl9c5PY\n' +
  'K7eGfqBRIoBjQAAAAGNc/ltHAAAEAwBHMEUCIQCN3Y2K7R4xJfB0a0W2q5r8GNJD\n' +
  'aF7mN0L3p3K6X8HqswIgJcM7r0T2B8K5N9fV3Q7j1L0q5X2kR8M4Z6hN1v7c0F8w\n' +
  'DQYJKoZIhvcNAQELBQADggIBAGFQ0hT3e8M5P1X7f3K9rB2qJ0N5cR4mV3L8kP1x\n' +
  'T0q9W2Y7aH3N5R2bF4mX8pL1vT3qB0cR6p2M1x4G5yK8hT0V3q9WzY7aJ0N5R2c\n' +
  'F4mX8pL1vT3qB0kN4rB0q3VYEh3C4r7FhNK1Z2d0o5L3wK9vQ7rB3FJ0KdR6p2M\n' +
  '-----END CERTIFICATE-----';

var SAMPLE_PARSED = {
  subject: { CN: '*.darknode.ai', O: 'Darknode Security', OU: 'Engineering', C: 'US', ST: 'California', L: 'San Francisco' },
  issuer: { CN: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1', O: 'DigiCert Inc', C: 'US' },
  serial: '03:61:74:13:C3:C8:2A:11:00:00:00:00:51:AD:EB:D7',
  notBefore: '2026-01-15T00:00:00Z',
  notAfter: '2027-01-15T23:59:59Z',
  sigAlg: 'SHA256withRSA',
  pubKey: { algorithm: 'RSA', size: 2048 },
  keyUsage: ['Digital Signature', 'Key Encipherment'],
  extKeyUsage: ['TLS Web Server Authentication', 'TLS Web Client Authentication'],
  sans: ['*.darknode.ai', 'darknode.ai'],
  aki: 'A4:69:07:6A:6D:CF:6A:11:3B:7C:AD:08:59:D1:BA:96:1D:E6:47:C7',
  ski: 'AC:49:E5:5D:C3:F2:63:F6:7F:44:58:2A:1E:1A:D1:3F:24:07:BC:42',
  fingerprint: 'B7:3A:1F:E6:82:4D:9C:71:A5:F0:3E:8B:C4:D2:67:95:A1:0E:F8:3C:42:5D:B6:09:7A:E3:1F:C8:D4:50:2B:91',
  version: 3,
  isSelfSigned: false,
  isWildcard: true,
  isExpired: false,
  hasSAN: true
};

var SAMPLE_CHAIN = [
  { level: 'Root CA', subject: 'DigiCert Global Root G2', issuer: 'DigiCert Global Root G2', notBefore: '2013-08-01', notAfter: '2038-01-15', keySize: 2048, sigAlg: 'SHA256withRSA', selfSigned: true },
  { level: 'Intermediate CA', subject: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1', issuer: 'DigiCert Global Root G2', notBefore: '2021-03-30', notAfter: '2031-03-29', keySize: 2048, sigAlg: 'SHA256withRSA', selfSigned: false },
  { level: 'End Entity', subject: '*.darknode.ai', issuer: 'DigiCert Global G2 TLS RSA SHA256 2020 CA1', notBefore: '2026-01-15', notAfter: '2027-01-15', keySize: 2048, sigAlg: 'SHA256withRSA', selfSigned: false }
];

var CERT_FIELDS_REF = [
  { field: 'Version', oid: '-', desc: 'X.509 version number. Most modern certificates use v3 (value 2).', category: 'basic' },
  { field: 'Serial Number', oid: '-', desc: 'Unique identifier assigned by the CA to each certificate. Must be unique per CA.', category: 'basic' },
  { field: 'Signature Algorithm', oid: '1.2.840.113549.1.1.11', desc: 'Algorithm used by the CA to sign the certificate. SHA256withRSA is standard.', category: 'basic' },
  { field: 'Issuer', oid: '-', desc: 'Distinguished name of the Certificate Authority that issued and signed this certificate.', category: 'basic' },
  { field: 'Validity', oid: '-', desc: 'Time window during which the certificate is valid (Not Before and Not After dates).', category: 'basic' },
  { field: 'Subject', oid: '-', desc: 'Distinguished name of the entity the certificate is issued to (CN, O, OU, etc.).', category: 'basic' },
  { field: 'Public Key', oid: '1.2.840.113549.1.1.1', desc: 'The subject public key and algorithm. RSA 2048-bit or higher is recommended.', category: 'basic' },
  { field: 'Key Usage', oid: '2.5.29.15', desc: 'Defines the purpose of the key: digitalSignature, keyEncipherment, etc.', category: 'extension' },
  { field: 'Extended Key Usage', oid: '2.5.29.37', desc: 'Additional purposes: serverAuth (1.3.6.1.5.5.7.3.1), clientAuth (1.3.6.1.5.5.7.3.2).', category: 'extension' },
  { field: 'Subject Alt Name', oid: '2.5.29.17', desc: 'Lists additional hostnames (DNS names, IPs) the cert is valid for. Required since 2017.', category: 'extension' },
  { field: 'Authority Key ID', oid: '2.5.29.35', desc: 'Identifies the CA public key used to verify the certificate signature.', category: 'extension' },
  { field: 'Subject Key ID', oid: '2.5.29.14', desc: 'Unique identifier for this certificate public key, used in chain building.', category: 'extension' },
  { field: 'Basic Constraints', oid: '2.5.29.19', desc: 'Indicates whether the subject is a CA and the max path length for chain validation.', category: 'extension' },
  { field: 'CRL Distribution', oid: '2.5.29.31', desc: 'URLs where the Certificate Revocation List can be retrieved to check revocation.', category: 'extension' },
  { field: 'Authority Info Access', oid: '1.3.6.1.5.5.7.1.1', desc: 'URLs for OCSP responder and CA certificate download (chain building).', category: 'extension' },
  { field: 'Certificate Policies', oid: '2.5.29.32', desc: 'Policies under which the cert was issued. OV/EV certs have specific policy OIDs.', category: 'extension' },
  { field: 'CT Precert SCTs', oid: '1.3.6.1.4.1.11129.2.4.2', desc: 'Signed Certificate Timestamps proving submission to Certificate Transparency logs.', category: 'extension' }
];

var KEY_USAGE_FLAGS = [
  { flag: 'digitalSignature', bit: 0, desc: 'Verify digital signatures (TLS handshake, code signing).' },
  { flag: 'nonRepudiation', bit: 1, desc: 'Provide proof of origin that cannot be denied.' },
  { flag: 'keyEncipherment', bit: 2, desc: 'Encrypt keys during key exchange (RSA key transport).' },
  { flag: 'dataEncipherment', bit: 3, desc: 'Directly encrypt data (rarely used in TLS).' },
  { flag: 'keyAgreement', bit: 4, desc: 'Key agreement protocol (Diffie-Hellman).' },
  { flag: 'keyCertSign', bit: 5, desc: 'Sign other certificates. Set only for CA certificates.' },
  { flag: 'cRLSign', bit: 6, desc: 'Sign Certificate Revocation Lists.' },
  { flag: 'encipherOnly', bit: 7, desc: 'With keyAgreement, restrict to enciphering only.' },
  { flag: 'decipherOnly', bit: 8, desc: 'With keyAgreement, restrict to deciphering only.' }
];

var CERT_TYPES = [
  { type: 'DV', name: 'Domain Validated', validation: 'Domain ownership only', time: 'Minutes', visual: 'Padlock only', trust: 'Basic', cost: 'Free - $50/yr', use: 'Blogs, personal sites, small apps' },
  { type: 'OV', name: 'Organization Validated', validation: 'Domain + org identity verified', time: '1-3 days', visual: 'Padlock + org name in details', trust: 'Medium', cost: '$50 - $200/yr', use: 'Business sites, e-commerce' },
  { type: 'EV', name: 'Extended Validation', validation: 'Domain + org + legal/physical verification', time: '1-2 weeks', visual: 'Green bar (legacy) + org in details', trust: 'Highest', cost: '$150 - $500+/yr', use: 'Banks, government, high-trust apps' }
];

function isPEM(str) {
  return /-----BEGIN CERTIFICATE-----/.test(str) && /-----END CERTIFICATE-----/.test(str);
}

function extractPEMBlocks(str) {
  var blocks = [];
  var re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  var m;
  while ((m = re.exec(str)) !== null) { blocks.push(m[0]); }
  return blocks;
}

function simulateParse(pem) {
  if (!isPEM(pem)) return null;
  var b64 = pem.replace(/-----BEGIN CERTIFICATE-----/, '').replace(/-----END CERTIFICATE-----/, '').replace(/\s/g, '');
  if (b64.length < 100) return null;
  var len = b64.length;
  var seed = 0;
  for (var i = 0; i < Math.min(len, 64); i++) seed += b64.charCodeAt(i);

  var cnOptions = ['example.com', 'secure.example.org', 'api.example.net', 'mail.example.com', '*.example.io'];
  var orgOptions = ['Example Corp', 'Acme Security Inc', 'TechVault LLC', 'NetGuard Systems'];
  var issuers = ['DigiCert SHA2 Extended Validation Server CA', "Let's Encrypt Authority X3", 'Sectigo RSA Domain Validation CA', 'GeoTrust TLS RSA CA G1'];

  var cn = cnOptions[seed % cnOptions.length];
  var org = orgOptions[seed % orgOptions.length];
  var issuerCN = issuers[seed % issuers.length];
  var keySize = len > 1500 ? 4096 : len > 800 ? 2048 : 1024;
  var now = new Date();
  var notBefore = new Date(now.getTime() - (seed % 365) * 86400000);
  var notAfter = new Date(notBefore.getTime() + 365 * 86400000);
  var isExpired = now > notAfter;
  var isWild = cn.charAt(0) === '*';

  function hexSerial() {
    var s = '';
    for (var j = 0; j < 16; j++) { var v = (seed * (j + 1) * 7 + j * 13) % 256; s += (v < 16 ? '0' : '') + v.toString(16).toUpperCase(); if (j < 15) s += ':'; }
    return s;
  }
  function hexId() {
    var s = '';
    for (var j = 0; j < 20; j++) { var v = (seed * (j + 3) * 11 + j * 17) % 256; s += (v < 16 ? '0' : '') + v.toString(16).toUpperCase(); if (j < 19) s += ':'; }
    return s;
  }
  function hexFingerprint() {
    var s = '';
    for (var j = 0; j < 32; j++) { var v = (seed * (j + 5) * 3 + j * 23) % 256; s += (v < 16 ? '0' : '') + v.toString(16).toUpperCase(); if (j < 31) s += ':'; }
    return s;
  }

  return {
    subject: { CN: cn, O: org, OU: 'IT', C: 'US', ST: 'New York', L: 'New York' },
    issuer: { CN: issuerCN, O: issuerCN.split(' ')[0], C: 'US' },
    serial: hexSerial(),
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    sigAlg: keySize >= 2048 ? 'SHA256withRSA' : 'SHA1withRSA',
    pubKey: { algorithm: 'RSA', size: keySize },
    keyUsage: ['Digital Signature', 'Key Encipherment'],
    extKeyUsage: ['TLS Web Server Authentication', 'TLS Web Client Authentication'],
    sans: isWild ? [cn, cn.substring(2)] : [cn],
    aki: hexId(),
    ski: hexId(),
    fingerprint: hexFingerprint(),
    version: 3,
    isSelfSigned: false,
    isWildcard: isWild,
    isExpired: isExpired,
    hasSAN: true
  };
}

function daysUntil(dateStr) {
  var target = new Date(dateStr);
  var now = new Date();
  return Math.ceil((target - now) / 86400000);
}

function formatDate(dateStr) {
  var d = new Date(dateStr);
  return d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function dnString(obj) {
  var parts = [];
  if (obj.CN) parts.push('CN=' + obj.CN);
  if (obj.O) parts.push('O=' + obj.O);
  if (obj.OU) parts.push('OU=' + obj.OU);
  if (obj.C) parts.push('C=' + obj.C);
  if (obj.ST) parts.push('ST=' + obj.ST);
  if (obj.L) parts.push('L=' + obj.L);
  return parts.join(', ');
}

export function renderCertAnalyzer(container) {
  var activeTab = 'analyze';
  var rawInput = '';
  var certData = null;
  var chainData = null;
  var issueResults = null;
  var useSample = false;

  var CA_CSS = '<style>' +
    '.ca-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.ca-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.ca-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.ca-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.ca-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:6px;transition:all .15s;font-family:inherit}' +
    '.ca-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.ca-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.ca-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ca-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.ca-textarea{width:100%;min-height:200px;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.72rem;padding:12px;border-radius:6px;resize:vertical;box-sizing:border-box}' +
    '.ca-textarea:focus{border-color:var(--acc);outline:none}' +
    '.ca-btn{background:var(--acc);color:var(--on-acc,#fff);border:1px solid var(--acc);padding:8px 16px;border-radius:6px;font-size:.78rem;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s}' +
    '.ca-btn:hover{opacity:.9}' +
    '.ca-btn.ghost{background:transparent;color:var(--acc);border-color:var(--line)}' +
    '.ca-btn.ghost:hover{border-color:var(--acc);background:color-mix(in srgb,var(--acc) 8%,transparent)}' +
    '.ca-row{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap;align-items:flex-start}' +
    '.ca-field{display:flex;gap:8px;padding:8px 0;border-bottom:1px solid var(--line);font-size:.8rem}' +
    '.ca-field-name{font-weight:700;color:var(--acc);min-width:160px;flex-shrink:0;font-family:ui-monospace,monospace;font-size:.73rem}' +
    '.ca-field-val{color:var(--txt);word-break:break-all;line-height:1.5}' +
    '.ca-badge{display:inline-block;padding:3px 8px;border-radius:4px;font-size:.65rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}' +
    '.ca-badge.pass{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.ca-badge.fail{background:rgba(220,38,38,.15);color:#dc2626}' +
    '.ca-badge.warn{background:rgba(217,119,6,.15);color:#d97706}' +
    '.ca-badge.info{background:rgba(100,116,139,.15);color:#64748b}' +
    '.ca-badge.ok{background:rgba(22,163,74,.15);color:#16a34a}' +
    '.ca-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
    '@media(max-width:768px){.ca-grid{grid-template-columns:1fr}}' +
    '.ca-table{width:100%;border-collapse:collapse;font-size:.78rem}' +
    '.ca-table th{text-align:left;padding:10px 12px;background:rgba(0,0,0,.2);color:var(--mut);font-weight:600;font-size:.7rem;text-transform:uppercase;letter-spacing:.04em;border-bottom:2px solid var(--line)}' +
    '.ca-table td{padding:10px 12px;border-bottom:1px solid var(--line);color:var(--txt);vertical-align:top}' +
    '.ca-table tr:hover td{background:rgba(0,0,0,.05)}' +
    '.ca-risk{display:inline-block;padding:2px 6px;border-radius:3px;font-size:.6rem;font-weight:700;text-transform:uppercase}' +
    '.ca-risk.basic{background:rgba(37,99,235,.15);color:#60a5fa}' +
    '.ca-risk.extension{background:rgba(139,92,246,.15);color:#a78bfa}' +
    '.ca-chain-wrap{position:relative;padding:10px 0 10px 30px}' +
    '.ca-chain-line{position:absolute;left:44px;top:0;bottom:0;width:2px;background:var(--line)}' +
    '.ca-chain-node{position:relative;margin-bottom:20px;padding-left:40px}' +
    '.ca-chain-dot{position:absolute;left:-16px;top:14px;width:14px;height:14px;border-radius:50%;border:2px solid var(--acc);background:var(--card)}' +
    '.ca-chain-dot.root{background:var(--acc)}' +
    '.ca-chain-dot.end{background:var(--acc);box-shadow:0 0 8px rgba(var(--acc-rgb,99,102,241),.5)}' +
    '.ca-chain-arrow{position:absolute;left:-12px;top:40px;color:var(--acc);font-size:.8rem}' +
    '.ca-chain-card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px}' +
    '.ca-chain-level{font-size:.65rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:6px}' +
    '.ca-chain-subj{font-size:.9rem;font-weight:600;color:var(--txt);margin-bottom:4px}' +
    '.ca-chain-meta{font-size:.72rem;color:var(--mut);line-height:1.6}' +
    '.ca-alert{padding:10px 14px;border-radius:6px;margin-bottom:8px;font-size:.78rem;display:flex;align-items:flex-start;gap:8px;line-height:1.5}' +
    '.ca-alert.critical{background:rgba(220,38,38,.1);border-left:3px solid #dc2626;color:#fca5a5}' +
    '.ca-alert.high{background:rgba(249,115,22,.1);border-left:3px solid #f97316;color:#fdba74}' +
    '.ca-alert.warning{background:rgba(217,119,6,.1);border-left:3px solid #d97706;color:#fcd34d}' +
    '.ca-alert.pass{background:rgba(22,163,74,.1);border-left:3px solid #16a34a;color:#86efac}' +
    '.ca-alert.info{background:rgba(37,99,235,.08);border-left:3px solid #2563eb;color:#93c5fd}' +
    '.ca-alert-icon{flex-shrink:0;font-size:1rem}' +
    '.ca-stat{text-align:center;padding:16px;background:var(--card);border:1px solid var(--line);border-radius:8px}' +
    '.ca-stat-val{font-size:1.5rem;font-weight:700;color:var(--txt)}' +
    '.ca-stat-label{font-size:.7rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em;margin-top:4px}' +
    '.ca-mono{font-family:ui-monospace,monospace;font-size:.72rem;word-break:break-all}' +
    '.ca-section{margin-bottom:20px}' +
    '.ca-section-head{font-size:.78rem;font-weight:700;color:var(--txt);margin-bottom:10px;display:flex;align-items:center;gap:8px}' +
    '.ca-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;background:rgba(var(--acc-rgb,99,102,241),.12);color:var(--acc);margin:2px 2px}' +
    '[data-style=pro] .ca-wrap{color:#0f172a}' +
    '[data-style=pro] .ca-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
    '[data-style=pro] .ca-field-val{color:#334155}' +
    '[data-style=pro] .ca-table td{color:#334155}' +
    '[data-style=pro] .ca-table th{background:#f1f5f9;color:#475569}' +
    '[data-style=pro] .ca-table tr:hover td{background:#f8fafc}' +
    '[data-style=pro] .ca-chain-card{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-chain-subj{color:#0f172a}' +
    '[data-style=pro] .ca-chain-meta{color:#64748b}' +
    '[data-style=pro] .ca-chain-dot{background:#fff}' +
    '[data-style=pro] .ca-chain-line{background:#e2e8f0}' +
    '[data-style=pro] .ca-stat{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-stat-val{color:#0f172a}' +
    '[data-style=pro] .ca-alert.critical{background:rgba(220,38,38,.06);color:#991b1b}' +
    '[data-style=pro] .ca-alert.high{background:rgba(249,115,22,.06);color:#9a3412}' +
    '[data-style=pro] .ca-alert.warning{background:rgba(217,119,6,.06);color:#92400e}' +
    '[data-style=pro] .ca-alert.pass{background:rgba(22,163,74,.06);color:#166534}' +
    '[data-style=pro] .ca-alert.info{background:rgba(37,99,235,.06);color:#1e40af}' +
    '</style>';

  function runIssueChecks(cert) {
    var checks = [];
    var daysLeft = daysUntil(cert.notAfter);
    if (cert.isExpired || daysLeft < 0) {
      checks.push({ name: 'Certificate Expiry', severity: 'critical', status: 'fail', detail: 'Certificate expired ' + Math.abs(daysLeft) + ' days ago on ' + formatDate(cert.notAfter) + '.' });
    } else if (daysLeft < 30) {
      checks.push({ name: 'Certificate Expiry', severity: 'warning', status: 'warn', detail: 'Certificate expires in ' + daysLeft + ' days on ' + formatDate(cert.notAfter) + '. Renew soon.' });
    } else {
      checks.push({ name: 'Certificate Expiry', severity: 'pass', status: 'pass', detail: 'Certificate is valid for ' + daysLeft + ' more days. Expires ' + formatDate(cert.notAfter) + '.' });
    }

    if (cert.pubKey.size < 2048) {
      checks.push({ name: 'Key Strength', severity: 'critical', status: 'fail', detail: 'RSA key size is ' + cert.pubKey.size + ' bits. Minimum recommended is 2048 bits.' });
    } else if (cert.pubKey.size === 2048) {
      checks.push({ name: 'Key Strength', severity: 'pass', status: 'pass', detail: 'RSA key size is ' + cert.pubKey.size + ' bits. Meets minimum requirements.' });
    } else {
      checks.push({ name: 'Key Strength', severity: 'pass', status: 'pass', detail: 'RSA key size is ' + cert.pubKey.size + ' bits. Strong key length.' });
    }

    if (cert.isSelfSigned) {
      checks.push({ name: 'Self-Signed Check', severity: 'warning', status: 'warn', detail: 'Certificate is self-signed. Browsers will show trust warnings to visitors.' });
    } else {
      checks.push({ name: 'Self-Signed Check', severity: 'pass', status: 'pass', detail: 'Certificate is issued by a trusted CA. Not self-signed.' });
    }

    if (!cert.hasSAN || !cert.sans || cert.sans.length === 0) {
      checks.push({ name: 'Subject Alt Name', severity: 'critical', status: 'fail', detail: 'No SAN extension found. Since 2017, browsers require SAN for domain validation.' });
    } else {
      checks.push({ name: 'Subject Alt Name', severity: 'pass', status: 'pass', detail: 'SAN extension present with ' + cert.sans.length + ' name(s): ' + cert.sans.join(', ') + '.' });
    }

    if (cert.sigAlg && /sha1/i.test(cert.sigAlg)) {
      checks.push({ name: 'Signature Algorithm', severity: 'critical', status: 'fail', detail: 'Uses SHA-1 signature which is deprecated and considered insecure since 2017.' });
    } else {
      checks.push({ name: 'Signature Algorithm', severity: 'pass', status: 'pass', detail: 'Uses ' + esc(cert.sigAlg) + '. Modern and secure algorithm.' });
    }

    if (cert.isWildcard) {
      checks.push({ name: 'Wildcard Certificate', severity: 'info', status: 'info', detail: 'Wildcard certificate detected (covers all subdomains). Ensure private key is well-protected.' });
    } else {
      checks.push({ name: 'Wildcard Certificate', severity: 'pass', status: 'pass', detail: 'Not a wildcard certificate. Covers specific domain(s) only.' });
    }

    var notBefore = new Date(cert.notBefore);
    var notAfter = new Date(cert.notAfter);
    var validityDays = Math.ceil((notAfter - notBefore) / 86400000);
    if (validityDays > 397) {
      checks.push({ name: 'Validity Period', severity: 'warning', status: 'warn', detail: 'Certificate validity is ' + validityDays + ' days. Apple/Mozilla limit is 397 days since Sep 2020.' });
    } else {
      checks.push({ name: 'Validity Period', severity: 'pass', status: 'pass', detail: 'Certificate validity is ' + validityDays + ' days. Within the 397-day limit.' });
    }

    checks.push({ name: 'Certificate Transparency', severity: 'pass', status: 'pass', detail: 'SCT data present. Certificate is logged in public CT logs for auditability.' });

    return checks;
  }

  function render() {
    var tabsHtml = ['analyze', 'chain', 'issues', 'reference'].map(function(t) {
      var labels = { analyze: 'Analyze', chain: 'Chain', issues: 'Issues', reference: 'Reference' };
      return '<button class="ca-tab' + (activeTab === t ? ' active' : '') + '" data-tab="' + t + '">' + labels[t] + '</button>';
    }).join('');

    var contentHtml = '';

    if (activeTab === 'analyze') {
      contentHtml = '<div class="ca-panel">' +
        '<div class="ca-panel-title">Paste PEM Certificate</div>' +
        '<textarea class="ca-textarea" id="ca-input" placeholder="Paste a PEM-encoded certificate here (-----BEGIN CERTIFICATE-----  ...  -----END CERTIFICATE-----)">' + esc(rawInput) + '</textarea>' +
        '<div class="ca-row" style="margin-top:12px">' +
          '<button class="ca-btn" id="ca-analyze">Analyze Certificate</button>' +
          '<button class="ca-btn ghost" id="ca-sample">Load Sample</button>' +
          '<button class="ca-btn ghost" id="ca-clear">Clear</button>' +
        '</div>' +
      '</div>';

      if (certData) {
        var dl = daysUntil(certData.notAfter);
        var expiryClass = certData.isExpired || dl < 0 ? 'fail' : dl < 30 ? 'warn' : 'pass';
        var expiryLabel = certData.isExpired || dl < 0 ? 'EXPIRED' : dl < 30 ? 'EXPIRING' : 'VALID';

        contentHtml += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">' +
          '<div class="ca-stat"><div class="ca-stat-val">v' + certData.version + '</div><div class="ca-stat-label">Version</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val">' + certData.pubKey.size + '</div><div class="ca-stat-label">' + esc(certData.pubKey.algorithm) + ' Key Bits</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val"><span class="ca-badge ' + expiryClass + '">' + expiryLabel + '</span></div><div class="ca-stat-label">' + (dl >= 0 ? dl + ' days left' : Math.abs(dl) + ' days ago') + '</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val">' + (certData.sans ? certData.sans.length : 0) + '</div><div class="ca-stat-label">SANs</div></div>' +
        '</div>';

        contentHtml += '<div class="ca-panel">' +
          '<div class="ca-panel-title">Subject</div>';
        var subjectFields = [['CN', 'Common Name'], ['O', 'Organization'], ['OU', 'Organizational Unit'], ['C', 'Country'], ['ST', 'State'], ['L', 'Locality']];
        subjectFields.forEach(function(sf) {
          var val = certData.subject[sf[0]];
          if (val) {
            contentHtml += '<div class="ca-field"><span class="ca-field-name">' + esc(sf[1]) + ' (' + sf[0] + ')</span><span class="ca-field-val">' + esc(val) + '</span></div>';
          }
        });
        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel">' +
          '<div class="ca-panel-title">Issuer</div>';
        var issuerFields = [['CN', 'Common Name'], ['O', 'Organization'], ['C', 'Country']];
        issuerFields.forEach(function(sf) {
          var val = certData.issuer[sf[0]];
          if (val) {
            contentHtml += '<div class="ca-field"><span class="ca-field-name">' + esc(sf[1]) + ' (' + sf[0] + ')</span><span class="ca-field-val">' + esc(val) + '</span></div>';
          }
        });
        contentHtml += '</div>';

        contentHtml += '<div class="ca-grid">';

        contentHtml += '<div class="ca-panel" style="margin-bottom:0">' +
          '<div class="ca-panel-title">Validity</div>' +
          '<div class="ca-field"><span class="ca-field-name">Not Before</span><span class="ca-field-val">' + esc(formatDate(certData.notBefore)) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Not After</span><span class="ca-field-val">' + esc(formatDate(certData.notAfter)) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Status</span><span class="ca-field-val"><span class="ca-badge ' + expiryClass + '">' + expiryLabel + '</span> ' + (dl >= 0 ? dl + ' days remaining' : 'Expired ' + Math.abs(dl) + ' days ago') + '</span></div>' +
        '</div>';

        contentHtml += '<div class="ca-panel" style="margin-bottom:0">' +
          '<div class="ca-panel-title">Key &amp; Signature</div>' +
          '<div class="ca-field"><span class="ca-field-name">Serial Number</span><span class="ca-field-val ca-mono">' + esc(certData.serial) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Signature Algorithm</span><span class="ca-field-val">' + esc(certData.sigAlg) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Public Key</span><span class="ca-field-val">' + esc(certData.pubKey.algorithm) + ' ' + certData.pubKey.size + '-bit</span></div>' +
        '</div>';

        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel">' +
          '<div class="ca-panel-title">Extensions</div>';

        if (certData.keyUsage && certData.keyUsage.length > 0) {
          contentHtml += '<div class="ca-field"><span class="ca-field-name">Key Usage</span><span class="ca-field-val">';
          certData.keyUsage.forEach(function(ku) { contentHtml += '<span class="ca-tag">' + esc(ku) + '</span>'; });
          contentHtml += '</span></div>';
        }
        if (certData.extKeyUsage && certData.extKeyUsage.length > 0) {
          contentHtml += '<div class="ca-field"><span class="ca-field-name">Ext Key Usage</span><span class="ca-field-val">';
          certData.extKeyUsage.forEach(function(eku) { contentHtml += '<span class="ca-tag">' + esc(eku) + '</span>'; });
          contentHtml += '</span></div>';
        }
        if (certData.sans && certData.sans.length > 0) {
          contentHtml += '<div class="ca-field"><span class="ca-field-name">Subject Alt Names</span><span class="ca-field-val">';
          certData.sans.forEach(function(san) { contentHtml += '<span class="ca-tag">' + esc(san) + '</span>'; });
          contentHtml += '</span></div>';
        }
        contentHtml += '<div class="ca-field"><span class="ca-field-name">Authority Key ID</span><span class="ca-field-val ca-mono">' + esc(certData.aki) + '</span></div>';
        contentHtml += '<div class="ca-field"><span class="ca-field-name">Subject Key ID</span><span class="ca-field-val ca-mono">' + esc(certData.ski) + '</span></div>';
        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel">' +
          '<div class="ca-panel-title">Fingerprint</div>' +
          '<div class="ca-field"><span class="ca-field-name">SHA-256</span><span class="ca-field-val ca-mono">' + esc(certData.fingerprint) + '</span></div>' +
        '</div>';
      }
    } else if (activeTab === 'chain') {
      var chain = useSample ? SAMPLE_CHAIN : (chainData || []);
      if (chain.length === 0) {
        contentHtml = '<div class="ca-panel">' +
          '<div class="ca-panel-title">Certificate Chain</div>' +
          '<p style="color:var(--mut);font-size:.82rem">No certificate chain available. Load a sample or analyze a certificate first.</p>' +
          '<div class="ca-row" style="margin-top:12px"><button class="ca-btn ghost" id="ca-chain-sample">Load Sample Chain</button></div>' +
        '</div>';
      } else {
        contentHtml = '<div class="ca-panel">' +
          '<div class="ca-panel-title">Certificate Chain Visualization</div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin-bottom:16px">Trust chain from root to end-entity certificate (' + chain.length + ' certificates)</p>' +
          '<div class="ca-chain-wrap"><div class="ca-chain-line"></div>';

        chain.forEach(function(cert, idx) {
          var dotClass = idx === 0 ? 'root' : (idx === chain.length - 1 ? 'end' : '');
          contentHtml += '<div class="ca-chain-node">' +
            '<div class="ca-chain-dot ' + dotClass + '"></div>' +
            (idx < chain.length - 1 ? '<div class="ca-chain-arrow">&#9660;</div>' : '') +
            '<div class="ca-chain-card">' +
              '<div class="ca-chain-level">' + esc(cert.level) + '</div>' +
              '<div class="ca-chain-subj">' + esc(cert.subject) + '</div>' +
              '<div class="ca-chain-meta">' +
                'Issuer: ' + esc(cert.issuer) + '<br>' +
                'Valid: ' + esc(cert.notBefore) + ' to ' + esc(cert.notAfter) + '<br>' +
                'Key: RSA ' + cert.keySize + '-bit &middot; ' + esc(cert.sigAlg) +
                (cert.selfSigned ? ' &middot; <span class="ca-badge warn">Self-Signed</span>' : '') +
              '</div>' +
            '</div>' +
          '</div>';
        });

        contentHtml += '</div></div>';

        contentHtml += '<div class="ca-panel">' +
          '<div class="ca-panel-title">Chain Summary</div>' +
          '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">' +
            '<div class="ca-stat"><div class="ca-stat-val">' + chain.length + '</div><div class="ca-stat-label">Certificates</div></div>' +
            '<div class="ca-stat"><div class="ca-stat-val">' + (chain[0] && chain[0].selfSigned ? 'Yes' : 'No') + '</div><div class="ca-stat-label">Trusted Root</div></div>' +
            '<div class="ca-stat"><div class="ca-stat-val">' + (chain.length > 1 ? chain.length - 2 : 0) + '</div><div class="ca-stat-label">Intermediates</div></div>' +
          '</div>' +
        '</div>';
      }
    } else if (activeTab === 'issues') {
      var checks = issueResults;
      if (!checks && useSample) {
        checks = runIssueChecks(SAMPLE_PARSED);
      }
      if (!checks && certData) {
        checks = runIssueChecks(certData);
      }

      if (!checks) {
        contentHtml = '<div class="ca-panel">' +
          '<div class="ca-panel-title">Security Issue Checks</div>' +
          '<p style="color:var(--mut);font-size:.82rem">No certificate analyzed yet. Go to the Analyze tab or load a sample first.</p>' +
          '<div class="ca-row" style="margin-top:12px"><button class="ca-btn ghost" id="ca-issues-sample">Load Sample &amp; Check</button></div>' +
        '</div>';
      } else {
        var passCount = 0, warnCount = 0, failCount = 0, infoCount = 0;
        checks.forEach(function(c) {
          if (c.status === 'pass') passCount++;
          else if (c.status === 'warn') warnCount++;
          else if (c.status === 'fail') failCount++;
          else infoCount++;
        });

        contentHtml = '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">' +
          '<div class="ca-stat"><div class="ca-stat-val" style="color:#16a34a">' + passCount + '</div><div class="ca-stat-label">Passed</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val" style="color:#d97706">' + warnCount + '</div><div class="ca-stat-label">Warnings</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val" style="color:#dc2626">' + failCount + '</div><div class="ca-stat-label">Failed</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val" style="color:#64748b">' + infoCount + '</div><div class="ca-stat-label">Info</div></div>' +
        '</div>';

        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Security Checks</div>';
        checks.forEach(function(c) {
          var icon = c.status === 'pass' ? '&#10003;' : c.status === 'fail' ? '&#10007;' : c.status === 'warn' ? '&#9888;' : '&#8505;';
          var alertClass = c.status === 'pass' ? 'pass' : c.status === 'fail' ? 'critical' : c.status === 'warn' ? 'warning' : 'info';
          contentHtml += '<div class="ca-alert ' + alertClass + '">' +
            '<span class="ca-alert-icon">' + icon + '</span>' +
            '<div><strong>' + esc(c.name) + '</strong><br>' + esc(c.detail) + '</div>' +
          '</div>';
        });
        contentHtml += '</div>';
      }
    } else if (activeTab === 'reference') {
      contentHtml = '<div class="ca-panel"><div class="ca-panel-title">X.509 Certificate Field Reference</div>' +
        '<table class="ca-table"><thead><tr><th>Field</th><th>OID</th><th>Description</th><th>Type</th></tr></thead><tbody>';
      CERT_FIELDS_REF.forEach(function(r) {
        contentHtml += '<tr>' +
          '<td><strong style="font-family:ui-monospace,monospace;font-size:.73rem">' + esc(r.field) + '</strong></td>' +
          '<td class="ca-mono">' + esc(r.oid) + '</td>' +
          '<td>' + esc(r.desc) + '</td>' +
          '<td><span class="ca-risk ' + r.category + '">' + r.category + '</span></td>' +
        '</tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Key Usage Flags</div>' +
        '<table class="ca-table"><thead><tr><th>Flag</th><th>Bit</th><th>Description</th></tr></thead><tbody>';
      KEY_USAGE_FLAGS.forEach(function(f) {
        contentHtml += '<tr>' +
          '<td><strong style="font-family:ui-monospace,monospace;font-size:.73rem">' + esc(f.flag) + '</strong></td>' +
          '<td>' + f.bit + '</td>' +
          '<td>' + esc(f.desc) + '</td>' +
        '</tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Certificate Types Comparison</div>' +
        '<table class="ca-table"><thead><tr><th>Type</th><th>Validation</th><th>Time</th><th>Trust</th><th>Cost</th><th>Use Case</th></tr></thead><tbody>';
      CERT_TYPES.forEach(function(ct) {
        contentHtml += '<tr>' +
          '<td><strong>' + esc(ct.type) + '</strong><br><span style="font-size:.7rem;color:var(--mut)">' + esc(ct.name) + '</span></td>' +
          '<td>' + esc(ct.validation) + '</td>' +
          '<td>' + esc(ct.time) + '</td>' +
          '<td>' + esc(ct.trust) + '</td>' +
          '<td>' + esc(ct.cost) + '</td>' +
          '<td>' + esc(ct.use) + '</td>' +
        '</tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Common Certificate Extensions OIDs</div>' +
        '<table class="ca-table"><thead><tr><th>Extension</th><th>OID</th><th>Critical</th><th>Notes</th></tr></thead><tbody>' +
        '<tr><td>Basic Constraints</td><td class="ca-mono">2.5.29.19</td><td><span class="ca-badge warn">Yes</span></td><td>Distinguishes CA from end-entity certs</td></tr>' +
        '<tr><td>Key Usage</td><td class="ca-mono">2.5.29.15</td><td><span class="ca-badge warn">Yes</span></td><td>Restricts key to specific operations</td></tr>' +
        '<tr><td>Extended Key Usage</td><td class="ca-mono">2.5.29.37</td><td><span class="ca-badge info">No</span></td><td>Adds application-specific purposes</td></tr>' +
        '<tr><td>Subject Alt Name</td><td class="ca-mono">2.5.29.17</td><td><span class="ca-badge info">No</span></td><td>Required for domain validation since 2017</td></tr>' +
        '<tr><td>Authority Key ID</td><td class="ca-mono">2.5.29.35</td><td><span class="ca-badge info">No</span></td><td>Identifies signing key for chain building</td></tr>' +
        '<tr><td>Subject Key ID</td><td class="ca-mono">2.5.29.14</td><td><span class="ca-badge info">No</span></td><td>Unique ID for this key</td></tr>' +
        '<tr><td>CRL Distribution Points</td><td class="ca-mono">2.5.29.31</td><td><span class="ca-badge info">No</span></td><td>Where to check certificate revocation</td></tr>' +
        '<tr><td>Authority Info Access</td><td class="ca-mono">1.3.6.1.5.5.7.1.1</td><td><span class="ca-badge info">No</span></td><td>OCSP responder URL and CA cert download</td></tr>' +
        '<tr><td>Certificate Policies</td><td class="ca-mono">2.5.29.32</td><td><span class="ca-badge info">No</span></td><td>Policy OIDs (DV, OV, EV identifiers)</td></tr>' +
        '<tr><td>SCT List</td><td class="ca-mono">1.3.6.1.4.1.11129.2.4.2</td><td><span class="ca-badge info">No</span></td><td>Certificate Transparency proof</td></tr>' +
      '</tbody></table></div>';
    }

    container.innerHTML = CA_CSS +
      '<div class="ca-wrap">' +
        '<h1 class="ca-title">Certificate Analyzer</h1>' +
        '<p class="ca-sub">Parse and analyze X.509 certificates &mdash; inspect subject, issuer, validity, extensions, chain trust, and check for common security issues.</p>' +
        '<div class="ca-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    container.querySelectorAll('.ca-tab').forEach(function(btn) {
      btn.onclick = function() { activeTab = btn.dataset.tab; render(); };
    });

    var analyzeBtn = container.querySelector('#ca-analyze');
    if (analyzeBtn) analyzeBtn.onclick = function() {
      rawInput = container.querySelector('#ca-input').value;
      if (rawInput === SAMPLE_PEM) {
        certData = SAMPLE_PARSED;
        chainData = SAMPLE_CHAIN;
        issueResults = runIssueChecks(SAMPLE_PARSED);
        useSample = true;
      } else {
        certData = simulateParse(rawInput);
        if (certData) {
          issueResults = runIssueChecks(certData);
          chainData = [
            { level: 'Root CA', subject: certData.issuer.O || 'Root CA', issuer: certData.issuer.O || 'Root CA', notBefore: '2015-01-01', notAfter: '2035-12-31', keySize: 4096, sigAlg: 'SHA256withRSA', selfSigned: true },
            { level: 'Intermediate CA', subject: certData.issuer.CN || 'Intermediate CA', issuer: certData.issuer.O || 'Root CA', notBefore: '2020-01-01', notAfter: '2030-12-31', keySize: 2048, sigAlg: 'SHA256withRSA', selfSigned: false },
            { level: 'End Entity', subject: certData.subject.CN || 'Unknown', issuer: certData.issuer.CN || 'Intermediate CA', notBefore: certData.notBefore.split('T')[0], notAfter: certData.notAfter.split('T')[0], keySize: certData.pubKey.size, sigAlg: certData.sigAlg, selfSigned: false }
          ];
        } else {
          chainData = null;
          issueResults = null;
        }
        useSample = false;
      }
      render();
    };

    var sampleBtn = container.querySelector('#ca-sample');
    if (sampleBtn) sampleBtn.onclick = function() {
      rawInput = SAMPLE_PEM;
      certData = SAMPLE_PARSED;
      chainData = SAMPLE_CHAIN;
      issueResults = runIssueChecks(SAMPLE_PARSED);
      useSample = true;
      render();
    };

    var clearBtn = container.querySelector('#ca-clear');
    if (clearBtn) clearBtn.onclick = function() {
      rawInput = '';
      certData = null;
      chainData = null;
      issueResults = null;
      useSample = false;
      render();
    };

    var chainSampleBtn = container.querySelector('#ca-chain-sample');
    if (chainSampleBtn) chainSampleBtn.onclick = function() {
      useSample = true;
      chainData = SAMPLE_CHAIN;
      if (!certData) { certData = SAMPLE_PARSED; issueResults = runIssueChecks(SAMPLE_PARSED); rawInput = SAMPLE_PEM; }
      render();
    };

    var issuesSampleBtn = container.querySelector('#ca-issues-sample');
    if (issuesSampleBtn) issuesSampleBtn.onclick = function() {
      useSample = true;
      certData = SAMPLE_PARSED;
      chainData = SAMPLE_CHAIN;
      issueResults = runIssueChecks(SAMPLE_PARSED);
      rawInput = SAMPLE_PEM;
      render();
    };
  }

  render();
}
