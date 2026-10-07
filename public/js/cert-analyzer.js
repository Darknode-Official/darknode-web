import { esc } from '/js/shared.js';
import { dnFetch, proxyConfigured } from '/js/net.js';

// Certificate Analyzer — REAL X.509 parsing.
//   * Paste PEM  -> decoded client-side with the inline ASN.1/DER parser below.
//   * Hostname   -> the newest leaf cert is pulled from crt.sh (CT logs) through
//                   the Darknode proxy, then parsed the same way.
// No fabricated/char-sum output. If parsing or a lookup fails, an honest error
// is shown and nothing is guessed.

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER X.509 parser (no external libraries).
// ---------------------------------------------------------------------------
function _x5b64ToBytes(b64) {
  var bin = atob(String(b64).replace(/[^A-Za-z0-9+/=]/g, ''));
  var out = new Uint8Array(bin.length);
  for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function _x5pemToDer(pem) {
  var m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem);
  return _x5b64ToBytes(m ? m[1] : pem);
}
function _x5node(b, pos) {
  var start = pos, first = b[pos++];
  var cls = first >> 6, constructed = (first & 0x20) !== 0, tag = first & 0x1f;
  if (tag === 0x1f) { tag = 0; var c; do { c = b[pos++]; tag = tag * 128 + (c & 0x7f); } while (c & 0x80); }
  var len = b[pos++], length;
  if (len < 0x80) length = len;
  else { var n = len & 0x7f; length = 0; for (var i = 0; i < n; i++) length = length * 256 + b[pos++]; }
  return { cls: cls, constructed: constructed, tag: tag, start: start, contentStart: pos, contentEnd: pos + length, end: pos + length };
}
function _x5children(b, node) {
  var out = [], p = node.contentStart;
  while (p < node.contentEnd) { var c = _x5node(b, p); out.push(c); if (c.end <= p) break; p = c.end; }
  return out;
}
function _x5oid(b, node) {
  var p = node.contentStart, end = node.contentEnd;
  if (p >= end) return '';
  var first = b[p++], s = Math.floor(first / 40) + '.' + (first % 40), v = 0;
  while (p < end) { var c = b[p++]; v = v * 128 + (c & 0x7f); if (!(c & 0x80)) { s += '.' + v; v = 0; } }
  return s;
}
function _x5strBytes(b, start, end) {
  try { return new TextDecoder('utf-8').decode(b.subarray(start, end)); }
  catch (e) { var s = ''; for (var i = start; i < end; i++) s += String.fromCharCode(b[i]); return s; }
}
function _x5hex(b, start, end) {
  var s = '';
  for (var i = start; i < end; i++) { var h = b[i].toString(16); if (h.length < 2) h = '0' + h; s += (s ? ':' : '') + h.toUpperCase(); }
  return s;
}
var _X5_DN = { '2.5.4.3':'CN','2.5.4.6':'C','2.5.4.7':'L','2.5.4.8':'ST','2.5.4.10':'O','2.5.4.11':'OU','2.5.4.5':'serialNumber','1.2.840.113549.1.9.1':'E','2.5.4.4':'SN','2.5.4.42':'GN','0.9.2342.19200300.100.1.25':'DC' };
function _x5dn(b, nameNode) {
  var out = {}, rdns = _x5children(b, nameNode);
  for (var i = 0; i < rdns.length; i++) {
    var atvs = _x5children(b, rdns[i]);
    for (var j = 0; j < atvs.length; j++) {
      var pair = _x5children(b, atvs[j]);
      if (pair.length < 2) continue;
      var oid = _x5oid(b, pair[0]);
      out[_X5_DN[oid] || oid] = _x5strBytes(b, pair[1].contentStart, pair[1].contentEnd);
    }
  }
  return out;
}
function _x5dnStr(dn) {
  var order = ['CN','OU','O','L','ST','C','E'], parts = [];
  for (var i = 0; i < order.length; i++) if (dn[order[i]]) parts.push(order[i] + '=' + dn[order[i]]);
  Object.keys(dn).forEach(function(k) { if (order.indexOf(k) === -1) parts.push(k + '=' + dn[k]); });
  return parts.join(', ');
}
function _x5time(b, node) {
  var s = _x5strBytes(b, node.contentStart, node.contentEnd), m;
  if (node.tag === 23) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s);
    if (!m) return null;
    var yy = parseInt(m[1], 10), year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
}
var _X5_SIG = { '1.2.840.113549.1.1.11':'SHA256withRSA','1.2.840.113549.1.1.12':'SHA384withRSA','1.2.840.113549.1.1.13':'SHA512withRSA','1.2.840.113549.1.1.5':'SHA1withRSA','1.2.840.113549.1.1.4':'MD5withRSA','1.2.840.113549.1.1.10':'RSASSA-PSS','1.2.840.10045.4.3.2':'ECDSAwithSHA256','1.2.840.10045.4.3.3':'ECDSAwithSHA384','1.2.840.10045.4.3.4':'ECDSAwithSHA512','1.3.101.112':'Ed25519','1.3.101.113':'Ed448' };
var _X5_EC = { '1.2.840.10045.3.1.7':256,'1.3.132.0.34':384,'1.3.132.0.35':521,'1.3.132.0.33':224 };
var _X5_EKU = { '1.3.6.1.5.5.7.3.1':'TLS Web Server Authentication','1.3.6.1.5.5.7.3.2':'TLS Web Client Authentication','1.3.6.1.5.5.7.3.3':'Code Signing','1.3.6.1.5.5.7.3.4':'Email Protection','1.3.6.1.5.5.7.3.8':'Time Stamping','1.3.6.1.5.5.7.3.9':'OCSP Signing' };
var _X5_KU = ['digitalSignature','nonRepudiation','keyEncipherment','dataEncipherment','keyAgreement','keyCertSign','cRLSign','encipherOnly','decipherOnly'];
var _X5_KU_FRIENDLY = { digitalSignature:'Digital Signature', nonRepudiation:'Non-Repudiation', keyEncipherment:'Key Encipherment', dataEncipherment:'Data Encipherment', keyAgreement:'Key Agreement', keyCertSign:'Certificate Signing', cRLSign:'CRL Signing', encipherOnly:'Encipher Only', decipherOnly:'Decipher Only' };
function _x5collectURIs(b, node, out) {
  if (node.constructed) { var ch = _x5children(b, node); for (var i = 0; i < ch.length; i++) _x5collectURIs(b, ch[i], out); }
  else if (node.tag === 22 || (node.cls === 2 && node.tag === 6)) { var u = _x5strBytes(b, node.contentStart, node.contentEnd); if (/^(https?|ldap):/.test(u)) out.push(u); }
}
async function _x5sha256(der) {
  try {
    if (!(typeof crypto !== 'undefined' && crypto.subtle)) return '';
    var copy = new Uint8Array(der);
    var buf = await crypto.subtle.digest('SHA-256', copy.buffer);
    var arr = new Uint8Array(buf), s = '';
    for (var i = 0; i < arr.length; i++) { var h = arr[i].toString(16); if (h.length < 2) h = '0' + h; s += (s ? ':' : '') + h.toUpperCase(); }
    return s;
  } catch (e) { return ''; }
}
async function _x5parse(der) {
  var cert = _x5node(der, 0);
  var top = _x5children(der, cert);
  var tbs = top[0], sigAlgNode = top[1];
  var tc = _x5children(der, tbs);
  var idx = 0, version = 1;
  if (tc[0] && tc[0].cls === 2 && tc[0].tag === 0) { var vi = _x5children(der, tc[0])[0]; version = (vi ? der[vi.contentEnd - 1] : 0) + 1; idx = 1; }
  var serialNode = tc[idx++]; idx++; // skip tbs signature alg
  var issuerNode = tc[idx++], validityNode = tc[idx++], subjectNode = tc[idx++], spkiNode = tc[idx++];
  var extNode = null;
  for (var k = idx; k < tc.length; k++) { if (tc[k].cls === 2 && tc[k].tag === 3) { extNode = tc[k]; break; } }

  var validity = _x5children(der, validityNode);
  var notBefore = validity[0] ? _x5time(der, validity[0]) : null;
  var notAfter = validity[1] ? _x5time(der, validity[1]) : null;
  var sigOid = _x5oid(der, _x5children(der, sigAlgNode)[0]);

  var spki = _x5children(der, spkiNode);
  var keyAlg = _x5children(der, spki[0]);
  var keyOid = _x5oid(der, keyAlg[0]);
  var keyType = 'Unknown', keySize = 0, bitStr = spki[1];
  if (keyOid === '1.2.840.113549.1.1.1') {
    keyType = 'RSA';
    try { var rsaSeq = _x5node(der, bitStr.contentStart + 1); var modulus = _x5children(der, rsaSeq)[0]; var ms = modulus.contentStart, me = modulus.contentEnd; while (ms < me && der[ms] === 0) ms++; keySize = (me - ms) * 8; } catch (e) {}
  } else if (keyOid === '1.2.840.10045.2.1') { keyType = 'EC'; keySize = keyAlg[1] ? (_X5_EC[_x5oid(der, keyAlg[1])] || 0) : 0; }
  else if (keyOid === '1.3.101.112') { keyType = 'Ed25519'; keySize = 256; }
  else if (keyOid === '1.3.101.113') { keyType = 'Ed448'; keySize = 456; }

  var subject = _x5dn(der, subjectNode), issuer = _x5dn(der, issuerNode);
  var sans = [], keyUsage = [], extKeyUsage = [], crl = [], ocsp = [], caIssuers = [], akiHex = '', skiHex = '', hasSCT = false, basicCA = false, pathLen = null;
  if (extNode) {
    var extSeq = _x5children(der, extNode)[0];
    var exts = extSeq ? _x5children(der, extSeq) : [];
    for (var e = 0; e < exts.length; e++) {
      var ecc = _x5children(der, exts[e]);
      if (!ecc.length) continue;
      var eoid = _x5oid(der, ecc[0]);
      var octet = ecc[ecc.length - 1], vstart = octet.contentStart;
      try {
        if (eoid === '2.5.29.17') {
          var gn = _x5children(der, _x5node(der, vstart));
          for (var g = 0; g < gn.length; g++) {
            var nn = gn[g];
            if (nn.tag === 2 || nn.tag === 1) sans.push(_x5strBytes(der, nn.contentStart, nn.contentEnd));
            else if (nn.tag === 7 && (nn.contentEnd - nn.contentStart) === 4) sans.push([der[nn.contentStart], der[nn.contentStart + 1], der[nn.contentStart + 2], der[nn.contentStart + 3]].join('.'));
          }
        } else if (eoid === '2.5.29.37') {
          var eks = _x5children(der, _x5node(der, vstart));
          for (var x = 0; x < eks.length; x++) { var eo = _x5oid(der, eks[x]); extKeyUsage.push(_X5_EKU[eo] || eo); }
        } else if (eoid === '2.5.29.15') {
          var kuNode = _x5node(der, vstart), kb = kuNode.contentStart + 1;
          for (var bidx = 0; bidx < _X5_KU.length; bidx++) { var byteI = kb + (bidx >> 3); if (byteI >= kuNode.contentEnd) break; if ((der[byteI] >> (7 - (bidx & 7))) & 1) keyUsage.push(_X5_KU_FRIENDLY[_X5_KU[bidx]]); }
        } else if (eoid === '2.5.29.19') {
          var bc = _x5children(der, _x5node(der, vstart));
          for (var y = 0; y < bc.length; y++) { if (bc[y].tag === 1) basicCA = der[bc[y].contentStart] !== 0; else if (bc[y].tag === 2) pathLen = der[bc[y].contentEnd - 1]; }
        } else if (eoid === '2.5.29.35') {
          var akis = _x5children(der, _x5node(der, vstart));
          for (var z = 0; z < akis.length; z++) if (akis[z].cls === 2 && akis[z].tag === 0) akiHex = _x5hex(der, akis[z].contentStart, akis[z].contentEnd);
        } else if (eoid === '2.5.29.14') {
          var skiNode = _x5node(der, vstart); skiHex = _x5hex(der, skiNode.contentStart, skiNode.contentEnd);
        } else if (eoid === '2.5.29.31') {
          _x5collectURIs(der, _x5node(der, vstart), crl);
        } else if (eoid === '1.3.6.1.5.5.7.1.1') {
          var ads = _x5children(der, _x5node(der, vstart));
          for (var q = 0; q < ads.length; q++) { var adp = _x5children(der, ads[q]); if (adp.length < 2) continue; var am = _x5oid(der, adp[0]); var loc = adp[1]; var lu = _x5strBytes(der, loc.contentStart, loc.contentEnd); if (am === '1.3.6.1.5.5.7.48.1') ocsp.push(lu); else if (am === '1.3.6.1.5.5.7.48.2') caIssuers.push(lu); }
        } else if (eoid === '1.3.6.1.4.1.11129.2.4.2') { hasSCT = true; }
      } catch (ePerExt) {}
    }
  }
  var subjectStr = _x5dnStr(subject), issuerStr = _x5dnStr(issuer);
  var fingerprint = await _x5sha256(der);
  return {
    version: version, serialHex: _x5hex(der, serialNode.contentStart, serialNode.contentEnd),
    sigAlgOid: sigOid, sigAlgName: _X5_SIG[sigOid] || sigOid,
    subject: subject, issuer: issuer, subjectStr: subjectStr, issuerStr: issuerStr,
    notBefore: notBefore, notAfter: notAfter, keyType: keyType, keySize: keySize, keyAlgOid: keyOid,
    sans: sans, keyUsage: keyUsage, extKeyUsage: extKeyUsage, basicCA: basicCA, pathLen: pathLen,
    akiHex: akiHex, skiHex: skiHex, crl: crl, ocsp: ocsp, caIssuers: caIssuers, hasSCT: hasSCT,
    isSelfSigned: subjectStr === issuerStr && !!subjectStr, fingerprint: fingerprint
  };
}

function extractPEMBlocks(str) {
  var blocks = [], re = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, m;
  while ((m = re.exec(str)) !== null) blocks.push(m[0]);
  return blocks;
}

// Adapt a raw parse result to the shape the UI renders.
function toCertData(p) {
  return {
    subject: p.subject, issuer: p.issuer, serial: p.serialHex || '-',
    notBefore: p.notBefore ? p.notBefore.toISOString() : '', notAfter: p.notAfter ? p.notAfter.toISOString() : '',
    sigAlg: p.sigAlgName, pubKey: { algorithm: p.keyType, size: p.keySize },
    keyUsage: p.keyUsage, extKeyUsage: p.extKeyUsage, sans: p.sans,
    aki: p.akiHex || '-', ski: p.skiHex || '-', fingerprint: p.fingerprint || '(unavailable in this context)',
    version: p.version, isSelfSigned: p.isSelfSigned,
    isWildcard: p.sans.some(function(s) { return s.indexOf('*') === 0; }) || String(p.subject.CN || '').indexOf('*') === 0,
    isExpired: p.notAfter ? (Date.now() > p.notAfter.getTime()) : false,
    hasSAN: p.sans.length > 0, hasSCT: p.hasSCT, basicCA: p.basicCA, crl: p.crl, ocsp: p.ocsp
  };
}
function toChainEntry(p, idx) {
  return {
    level: p.isSelfSigned ? 'Root CA' : (idx === 0 ? 'End Entity' : 'Intermediate CA'),
    subject: p.subjectStr || p.subject.CN || 'Unknown', issuer: p.issuerStr || p.issuer.CN || 'Unknown',
    notBefore: p.notBefore ? p.notBefore.toISOString().split('T')[0] : '-', notAfter: p.notAfter ? p.notAfter.toISOString().split('T')[0] : '-',
    keyType: p.keyType, keySize: p.keySize, sigAlg: p.sigAlgName, selfSigned: p.isSelfSigned
  };
}

// Fetch the newest leaf certificate for a hostname from crt.sh (CT logs) via the proxy.
async function ctFetchPEM(host) {
  if (!proxyConfigured()) throw new Error('The Darknode proxy is not configured, so certificates cannot be fetched from CT logs.');
  var list = await dnFetch('https://crt.sh/?q=' + encodeURIComponent(host) + '&output=json&exclude=expired', { raw: true, timeout: 15000 });
  var arr; try { arr = JSON.parse(list.body); } catch (e) { throw new Error('crt.sh returned no parseable data for ' + host + '.'); }
  if (!Array.isArray(arr) || !arr.length) throw new Error('No certificates found in CT logs for ' + host + '.');
  arr.sort(function(a, b) { return (b.id || 0) - (a.id || 0); });
  var pem = await dnFetch('https://crt.sh/?d=' + encodeURIComponent(arr[0].id), { raw: true, timeout: 15000 });
  if (!/BEGIN CERTIFICATE/.test(pem.body || '')) throw new Error('Could not download the certificate PEM from crt.sh.');
  return pem.body;
}

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

function daysUntil(dateStr) { return Math.floor((new Date(dateStr) - new Date()) / 86400000); }
function formatDate(dateStr) { var d = new Date(dateStr); return isNaN(d) ? '-' : d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'); }

export function renderCertAnalyzer(container) {
  var activeTab = 'analyze';
  var rawInput = '';
  var certData = null;
  var chainData = null;
  var issueResults = null;

  var CA_CSS = '<style>' +
    '.ca-wrap{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#c8d6e5;max-width:1100px}' +
    '.ca-title{font-size:1.6rem;font-weight:700;margin:0 0 6px;color:var(--txt)}' +
    '.ca-sub{color:var(--mut);font-size:.85rem;margin-bottom:20px;line-height:1.5}' +
    '.ca-tabs{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:24px}' +
    '.ca-tab{background:var(--card);border:1px solid var(--line);color:var(--mut);padding:8px 16px;font-size:.75rem;font-weight:600;letter-spacing:.04em;text-transform:uppercase;cursor:pointer;border-radius:4px;transition:all .15s;font-family:inherit}' +
    '.ca-tab:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card));color:var(--txt)}' +
    '.ca-tab.active{background:var(--acc);color:var(--on-acc,#fff);border-color:var(--acc)}' +
    '.ca-panel{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:20px;margin-bottom:16px}' +
    '.ca-panel-title{font-size:.8rem;font-weight:700;text-transform:uppercase;letter-spacing:.06em;color:var(--acc);margin-bottom:12px}' +
    '.ca-input{width:100%;background:var(--card2,#0a0e14);border:1px solid var(--line);color:var(--txt);font-family:ui-monospace,monospace;font-size:.8rem;padding:10px 12px;border-radius:6px;box-sizing:border-box}' +
    '.ca-input:focus{border-color:var(--acc);outline:none}' +
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
    '.ca-tag{display:inline-block;padding:2px 8px;border-radius:4px;font-size:.65rem;font-weight:600;background:rgba(var(--acc-rgb,99,102,241),.12);color:var(--acc);margin:2px 2px}' +
    '[data-style=pro] .ca-wrap{color:#0f172a}' +
    '[data-style=pro] .ca-panel{background:#fff;border-color:#e2e8f0}' +
    '[data-style=pro] .ca-input,[data-style=pro] .ca-textarea{background:#f8fafc;border-color:#e2e8f0;color:#0f172a}' +
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
    if (cert.isExpired || daysLeft < 0) checks.push({ name: 'Certificate Expiry', status: 'fail', detail: 'Certificate expired ' + Math.abs(daysLeft) + ' days ago on ' + formatDate(cert.notAfter) + '.' });
    else if (daysLeft < 30) checks.push({ name: 'Certificate Expiry', status: 'warn', detail: 'Certificate expires in ' + daysLeft + ' days on ' + formatDate(cert.notAfter) + '. Renew soon.' });
    else checks.push({ name: 'Certificate Expiry', status: 'pass', detail: 'Certificate is valid for ' + daysLeft + ' more days. Expires ' + formatDate(cert.notAfter) + '.' });

    if (cert.pubKey.algorithm === 'RSA' && cert.pubKey.size && cert.pubKey.size < 2048) checks.push({ name: 'Key Strength', status: 'fail', detail: 'RSA key size is ' + cert.pubKey.size + ' bits. Minimum recommended is 2048 bits.' });
    else if (cert.pubKey.size) checks.push({ name: 'Key Strength', status: 'pass', detail: cert.pubKey.algorithm + ' key (' + cert.pubKey.size + ' bits). Meets modern requirements.' });
    else checks.push({ name: 'Key Strength', status: 'info', detail: 'Public key algorithm: ' + esc(cert.pubKey.algorithm) + '.' });

    if (cert.isSelfSigned) checks.push({ name: 'Self-Signed Check', status: 'warn', detail: 'Issuer equals subject — this certificate is self-signed. Browsers will show trust warnings unless it is a trusted root.' });
    else checks.push({ name: 'Self-Signed Check', status: 'pass', detail: 'Issued by a different authority (not self-signed).' });

    if (!cert.hasSAN || !cert.sans || cert.sans.length === 0) checks.push({ name: 'Subject Alt Name', status: 'fail', detail: 'No SAN extension found. Since 2017, browsers require SAN for domain validation.' });
    else checks.push({ name: 'Subject Alt Name', status: 'pass', detail: 'SAN extension present with ' + cert.sans.length + ' name(s): ' + cert.sans.join(', ') + '.' });

    if (cert.sigAlg && /sha1|md5/i.test(cert.sigAlg)) checks.push({ name: 'Signature Algorithm', status: 'fail', detail: 'Uses ' + esc(cert.sigAlg) + ' which is deprecated and insecure.' });
    else checks.push({ name: 'Signature Algorithm', status: 'pass', detail: 'Uses ' + esc(cert.sigAlg) + '. Modern and secure algorithm.' });

    if (cert.isWildcard) checks.push({ name: 'Wildcard Certificate', status: 'info', detail: 'Wildcard certificate detected (covers all subdomains). Ensure the private key is well-protected.' });
    else checks.push({ name: 'Wildcard Certificate', status: 'pass', detail: 'Not a wildcard certificate. Covers specific name(s) only.' });

    if (cert.notBefore && cert.notAfter) {
      var validityDays = Math.ceil((new Date(cert.notAfter) - new Date(cert.notBefore)) / 86400000);
      if (validityDays > 398) checks.push({ name: 'Validity Period', status: 'warn', detail: 'Certificate validity is ' + validityDays + ' days. Apple/Mozilla limit is 398 days since Sep 2020.' });
      else checks.push({ name: 'Validity Period', status: 'pass', detail: 'Certificate validity is ' + validityDays + ' days. Within the 398-day limit.' });
    }

    if (cert.hasSCT) checks.push({ name: 'Certificate Transparency', status: 'pass', detail: 'Embedded SCTs found. The certificate is logged in public CT logs for auditability.' });
    else checks.push({ name: 'Certificate Transparency', status: 'info', detail: 'No embedded SCTs found in this certificate (SCTs may instead be delivered via the TLS handshake or OCSP).' });

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
        '<div class="ca-panel-title">Analyze a Certificate</div>' +
        '<div class="ca-row" style="margin-bottom:10px">' +
          '<input class="ca-input" id="ca-host" style="flex:2;min-width:220px" placeholder="hostname (e.g. darknode.ai) — fetch the newest leaf cert from CT logs">' +
          '<button class="ca-btn ghost" id="ca-fetch">Fetch via crt.sh</button>' +
        '</div>' +
        '<textarea class="ca-textarea" id="ca-input" placeholder="...or paste one or more PEM blocks (-----BEGIN CERTIFICATE----- ... -----END CERTIFICATE-----). Multiple blocks are treated as a chain.">' + esc(rawInput) + '</textarea>' +
        '<div class="ca-row" style="margin-top:12px">' +
          '<button class="ca-btn" id="ca-analyze">Analyze Certificate</button>' +
          '<button class="ca-btn ghost" id="ca-clear">Clear</button>' +
        '</div>' +
        '<div id="ca-analyze-msg" style="color:var(--mut);font-size:.75rem;margin-top:4px"></div>' +
      '</div>';

      if (certData) {
        var dl = daysUntil(certData.notAfter);
        var expiryClass = certData.isExpired || dl < 0 ? 'fail' : dl < 30 ? 'warn' : 'pass';
        var expiryLabel = certData.isExpired || dl < 0 ? 'EXPIRED' : dl < 30 ? 'EXPIRING' : 'VALID';

        contentHtml += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:16px">' +
          '<div class="ca-stat"><div class="ca-stat-val">v' + certData.version + '</div><div class="ca-stat-label">Version</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val">' + (certData.pubKey.size || '-') + '</div><div class="ca-stat-label">' + esc(certData.pubKey.algorithm) + ' Key Bits</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val"><span class="ca-badge ' + expiryClass + '">' + expiryLabel + '</span></div><div class="ca-stat-label">' + (dl >= 0 ? dl + ' days left' : Math.abs(dl) + ' days ago') + '</div></div>' +
          '<div class="ca-stat"><div class="ca-stat-val">' + (certData.sans ? certData.sans.length : 0) + '</div><div class="ca-stat-label">SANs</div></div>' +
        '</div>';

        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Subject</div>';
        [['CN', 'Common Name'], ['O', 'Organization'], ['OU', 'Organizational Unit'], ['C', 'Country'], ['ST', 'State'], ['L', 'Locality']].forEach(function(sf) {
          var val = certData.subject[sf[0]];
          if (val) contentHtml += '<div class="ca-field"><span class="ca-field-name">' + esc(sf[1]) + ' (' + sf[0] + ')</span><span class="ca-field-val">' + esc(val) + '</span></div>';
        });
        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Issuer</div>';
        [['CN', 'Common Name'], ['O', 'Organization'], ['C', 'Country']].forEach(function(sf) {
          var val = certData.issuer[sf[0]];
          if (val) contentHtml += '<div class="ca-field"><span class="ca-field-name">' + esc(sf[1]) + ' (' + sf[0] + ')</span><span class="ca-field-val">' + esc(val) + '</span></div>';
        });
        contentHtml += '</div>';

        contentHtml += '<div class="ca-grid">';
        contentHtml += '<div class="ca-panel" style="margin-bottom:0"><div class="ca-panel-title">Validity</div>' +
          '<div class="ca-field"><span class="ca-field-name">Not Before</span><span class="ca-field-val">' + esc(formatDate(certData.notBefore)) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Not After</span><span class="ca-field-val">' + esc(formatDate(certData.notAfter)) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Status</span><span class="ca-field-val"><span class="ca-badge ' + expiryClass + '">' + expiryLabel + '</span> ' + (dl >= 0 ? dl + ' days remaining' : 'Expired ' + Math.abs(dl) + ' days ago') + '</span></div>' +
        '</div>';
        contentHtml += '<div class="ca-panel" style="margin-bottom:0"><div class="ca-panel-title">Key &amp; Signature</div>' +
          '<div class="ca-field"><span class="ca-field-name">Serial Number</span><span class="ca-field-val ca-mono">' + esc(certData.serial) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Signature Algorithm</span><span class="ca-field-val">' + esc(certData.sigAlg) + '</span></div>' +
          '<div class="ca-field"><span class="ca-field-name">Public Key</span><span class="ca-field-val">' + esc(certData.pubKey.algorithm) + (certData.pubKey.size ? ' ' + certData.pubKey.size + '-bit' : '') + '</span></div>' +
        '</div>';
        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Extensions</div>';
        if (certData.keyUsage && certData.keyUsage.length) { contentHtml += '<div class="ca-field"><span class="ca-field-name">Key Usage</span><span class="ca-field-val">'; certData.keyUsage.forEach(function(ku) { contentHtml += '<span class="ca-tag">' + esc(ku) + '</span>'; }); contentHtml += '</span></div>'; }
        if (certData.extKeyUsage && certData.extKeyUsage.length) { contentHtml += '<div class="ca-field"><span class="ca-field-name">Ext Key Usage</span><span class="ca-field-val">'; certData.extKeyUsage.forEach(function(eku) { contentHtml += '<span class="ca-tag">' + esc(eku) + '</span>'; }); contentHtml += '</span></div>'; }
        if (certData.sans && certData.sans.length) { contentHtml += '<div class="ca-field"><span class="ca-field-name">Subject Alt Names</span><span class="ca-field-val">'; certData.sans.forEach(function(san) { contentHtml += '<span class="ca-tag">' + esc(san) + '</span>'; }); contentHtml += '</span></div>'; }
        contentHtml += '<div class="ca-field"><span class="ca-field-name">Basic Constraints</span><span class="ca-field-val">' + (certData.basicCA ? 'CA:TRUE' : 'CA:FALSE') + '</span></div>';
        contentHtml += '<div class="ca-field"><span class="ca-field-name">Authority Key ID</span><span class="ca-field-val ca-mono">' + esc(certData.aki) + '</span></div>';
        contentHtml += '<div class="ca-field"><span class="ca-field-name">Subject Key ID</span><span class="ca-field-val ca-mono">' + esc(certData.ski) + '</span></div>';
        if (certData.ocsp && certData.ocsp.length) contentHtml += '<div class="ca-field"><span class="ca-field-name">OCSP</span><span class="ca-field-val ca-mono">' + esc(certData.ocsp.join(', ')) + '</span></div>';
        if (certData.crl && certData.crl.length) contentHtml += '<div class="ca-field"><span class="ca-field-name">CRL</span><span class="ca-field-val ca-mono">' + esc(certData.crl.join(', ')) + '</span></div>';
        contentHtml += '</div>';

        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Fingerprint</div>' +
          '<div class="ca-field"><span class="ca-field-name">SHA-256</span><span class="ca-field-val ca-mono">' + esc(certData.fingerprint) + '</span></div></div>';
      }
    } else if (activeTab === 'chain') {
      var chain = chainData || [];
      if (chain.length === 0) {
        contentHtml = '<div class="ca-panel"><div class="ca-panel-title">Certificate Chain</div>' +
          '<p style="color:var(--mut);font-size:.82rem">No certificate parsed yet. On the Analyze tab, paste the full PEM chain (end-entity + intermediates + root) to visualize the real chain of trust.</p></div>';
      } else {
        contentHtml = '<div class="ca-panel"><div class="ca-panel-title">Certificate Chain Visualization</div>' +
          '<p style="color:var(--mut);font-size:.78rem;margin-bottom:16px">' + (chain.length > 1 ? 'Trust chain parsed from the pasted PEM (' + chain.length + ' certificates)' : 'Only one certificate was provided — paste the full chain for a complete view.') + '</p>' +
          '<div class="ca-chain-wrap"><div class="ca-chain-line"></div>';
        chain.forEach(function(cert, idx) {
          var dotClass = idx === 0 ? 'root' : (idx === chain.length - 1 ? 'end' : '');
          contentHtml += '<div class="ca-chain-node"><div class="ca-chain-dot ' + dotClass + '"></div>' +
            (idx < chain.length - 1 ? '<div class="ca-chain-arrow">&#9660;</div>' : '') +
            '<div class="ca-chain-card"><div class="ca-chain-level">' + esc(cert.level) + '</div>' +
            '<div class="ca-chain-subj">' + esc(cert.subject) + '</div>' +
            '<div class="ca-chain-meta">Issuer: ' + esc(cert.issuer) + '<br>Valid: ' + esc(cert.notBefore) + ' to ' + esc(cert.notAfter) + '<br>Key: ' + esc(cert.keyType) + (cert.keySize ? ' ' + cert.keySize + '-bit' : '') + ' &middot; ' + esc(cert.sigAlg) +
            (cert.selfSigned ? ' &middot; <span class="ca-badge warn">Self-Signed</span>' : '') + '</div></div></div>';
        });
        contentHtml += '</div></div>';
        contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Chain Summary</div>' +
          '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px">' +
            '<div class="ca-stat"><div class="ca-stat-val">' + chain.length + '</div><div class="ca-stat-label">Certificates</div></div>' +
            '<div class="ca-stat"><div class="ca-stat-val">' + (chain.some(function(c) { return c.selfSigned; }) ? 'Yes' : 'No') + '</div><div class="ca-stat-label">Root Present</div></div>' +
            '<div class="ca-stat"><div class="ca-stat-val">' + chain.filter(function(c) { return c.level === 'Intermediate CA'; }).length + '</div><div class="ca-stat-label">Intermediates</div></div>' +
          '</div></div>';
      }
    } else if (activeTab === 'issues') {
      var checks = issueResults || (certData ? runIssueChecks(certData) : null);
      if (!checks) {
        contentHtml = '<div class="ca-panel"><div class="ca-panel-title">Security Issue Checks</div>' +
          '<p style="color:var(--mut);font-size:.82rem">No certificate analyzed yet. Go to the Analyze tab and parse a certificate first.</p></div>';
      } else {
        var passCount = 0, warnCount = 0, failCount = 0, infoCount = 0;
        checks.forEach(function(c) { if (c.status === 'pass') passCount++; else if (c.status === 'warn') warnCount++; else if (c.status === 'fail') failCount++; else infoCount++; });
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
          contentHtml += '<div class="ca-alert ' + alertClass + '"><span class="ca-alert-icon">' + icon + '</span><div><strong>' + esc(c.name) + '</strong><br>' + esc(c.detail) + '</div></div>';
        });
        contentHtml += '</div>';
      }
    } else if (activeTab === 'reference') {
      contentHtml = '<div class="ca-panel"><div class="ca-panel-title">X.509 Certificate Field Reference</div>' +
        '<table class="ca-table"><thead><tr><th>Field</th><th>OID</th><th>Description</th><th>Type</th></tr></thead><tbody>';
      CERT_FIELDS_REF.forEach(function(r) {
        contentHtml += '<tr><td><strong style="font-family:ui-monospace,monospace;font-size:.73rem">' + esc(r.field) + '</strong></td><td class="ca-mono">' + esc(r.oid) + '</td><td>' + esc(r.desc) + '</td><td><span class="ca-risk ' + r.category + '">' + r.category + '</span></td></tr>';
      });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Key Usage Flags</div>' +
        '<table class="ca-table"><thead><tr><th>Flag</th><th>Bit</th><th>Description</th></tr></thead><tbody>';
      KEY_USAGE_FLAGS.forEach(function(f) { contentHtml += '<tr><td><strong style="font-family:ui-monospace,monospace;font-size:.73rem">' + esc(f.flag) + '</strong></td><td>' + f.bit + '</td><td>' + esc(f.desc) + '</td></tr>'; });
      contentHtml += '</tbody></table></div>';

      contentHtml += '<div class="ca-panel"><div class="ca-panel-title">Certificate Types Comparison</div>' +
        '<table class="ca-table"><thead><tr><th>Type</th><th>Validation</th><th>Time</th><th>Trust</th><th>Cost</th><th>Use Case</th></tr></thead><tbody>';
      CERT_TYPES.forEach(function(ct) {
        contentHtml += '<tr><td><strong>' + esc(ct.type) + '</strong><br><span style="font-size:.7rem;color:var(--mut)">' + esc(ct.name) + '</span></td><td>' + esc(ct.validation) + '</td><td>' + esc(ct.time) + '</td><td>' + esc(ct.trust) + '</td><td>' + esc(ct.cost) + '</td><td>' + esc(ct.use) + '</td></tr>';
      });
      contentHtml += '</tbody></table></div>';
    }

    container.innerHTML = CA_CSS +
      '<div class="ca-wrap">' +
        '<h1 class="ca-title">Certificate Analyzer</h1>' +
        '<p class="ca-sub">Parse and analyze X.509 certificates &mdash; real client-side ASN.1/DER decoding of pasted PEM, or fetch a host’s live leaf certificate from Certificate Transparency logs. Inspect subject, issuer, validity, extensions, chain and security issues.</p>' +
        '<div class="ca-tabs">' + tabsHtml + '</div>' +
        contentHtml +
      '</div>';

    container.querySelectorAll('.ca-tab').forEach(function(btn) { btn.onclick = function() { activeTab = btn.dataset.tab; render(); }; });

    var analyzeBtn = container.querySelector('#ca-analyze');
    if (analyzeBtn) analyzeBtn.onclick = async function() {
      var msg = container.querySelector('#ca-analyze-msg');
      rawInput = (container.querySelector('#ca-input') || {}).value || '';
      var blocks = extractPEMBlocks(rawInput);
      if (!blocks.length) { certData = null; chainData = null; issueResults = null; if (msg) msg.textContent = 'No PEM certificate block found. Paste text between -----BEGIN CERTIFICATE----- and -----END CERTIFICATE-----.'; return; }
      if (msg) msg.textContent = 'Parsing ' + blocks.length + ' certificate(s)...';
      try {
        var parsed = [];
        for (var i = 0; i < blocks.length; i++) parsed.push(await _x5parse(_x5pemToDer(blocks[i])));
        certData = toCertData(parsed[0]);
        chainData = parsed.map(function(p, idx) { return toChainEntry(p, idx); });
        issueResults = runIssueChecks(certData);
        render();
      } catch (e) {
        certData = null; chainData = null; issueResults = null;
        if (msg) msg.textContent = 'Could not parse the certificate: ' + ((e && e.message) || 'malformed DER') + '. Make sure it is a valid PEM X.509 certificate.';
      }
    };

    var fetchBtn = container.querySelector('#ca-fetch');
    if (fetchBtn) fetchBtn.onclick = async function() {
      var host = ((container.querySelector('#ca-host') || {}).value || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/[/:].*$/, '');
      var msg = container.querySelector('#ca-analyze-msg');
      if (!host) { if (msg) msg.textContent = 'Enter a hostname to fetch its certificate from CT logs.'; return; }
      if (msg) msg.textContent = 'Fetching newest certificate for ' + host + ' from crt.sh...';
      try {
        var pem = await ctFetchPEM(host);
        rawInput = pem;
        var parsed = await _x5parse(_x5pemToDer(extractPEMBlocks(pem)[0] || pem));
        certData = toCertData(parsed);
        chainData = [toChainEntry(parsed, 0)];
        issueResults = runIssueChecks(certData);
        render();
      } catch (e) {
        certData = null; chainData = null; issueResults = null;
        if (msg) msg.textContent = (e && e.message) || 'Fetch failed.';
      }
    };

    var clearBtn = container.querySelector('#ca-clear');
    if (clearBtn) clearBtn.onclick = function() { rawInput = ''; certData = null; chainData = null; issueResults = null; render(); };
  }

  render();
}
