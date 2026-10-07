import { esc } from '/js/shared.js';
import { dnFetch, proxyConfigured } from '/js/net.js';

const SC_ALGOS = {
  'sha256WithRSAEncryption': { name: 'SHA-256 with RSA', strength: 'Strong', score: 10 },
  'sha384WithRSAEncryption': { name: 'SHA-384 with RSA', strength: 'Strong', score: 10 },
  'sha512WithRSAEncryption': { name: 'SHA-512 with RSA', strength: 'Strong', score: 10 },
  'sha1WithRSAEncryption': { name: 'SHA-1 with RSA', strength: 'Weak', score: 3 },
  'md5WithRSAEncryption': { name: 'MD5 with RSA', strength: 'Critical', score: 0 },
  'ecdsa-with-SHA256': { name: 'ECDSA with SHA-256', strength: 'Strong', score: 10 },
  'ecdsa-with-SHA384': { name: 'ECDSA with SHA-384', strength: 'Strong', score: 10 },
  'Ed25519': { name: 'Ed25519', strength: 'Strong', score: 10 }
};

const SC_KEY_SCORES = { 4096: 10, 3072: 9, 2048: 7, 1024: 3, 512: 0 };
const SC_ECC_SCORES = { 521: 10, 384: 10, 256: 9, 224: 5 };

function scGrade(score) {
  if (score >= 90) return { grade: 'A+', color: '#00ff88', bg: 'rgba(0,255,136,0.1)' };
  if (score >= 80) return { grade: 'A', color: '#00ff88', bg: 'rgba(0,255,136,0.1)' };
  if (score >= 70) return { grade: 'B', color: '#00aaff', bg: 'rgba(0,170,255,0.1)' };
  if (score >= 60) return { grade: 'C', color: '#ffd600', bg: 'rgba(255,214,0,0.1)' };
  if (score >= 40) return { grade: 'D', color: '#ff9100', bg: 'rgba(255,145,0,0.1)' };
  return { grade: 'F', color: '#ff4444', bg: 'rgba(255,68,68,0.1)' };
}

function scParsePEM(pem) {
  const lines = pem.trim().split('\n');
  const certs = [];
  let current = [];
  let inCert = false;
  for (const line of lines) {
    if (line.includes('BEGIN CERTIFICATE')) { inCert = true; current = [line]; }
    else if (line.includes('END CERTIFICATE')) { current.push(line); certs.push(current.join('\n')); inCert = false; }
    else if (inCert) current.push(line);
  }
  return certs;
}

// ---------------------------------------------------------------------------
// Minimal ASN.1 DER X.509 / PKCS#10 parser (no external libraries) — real decode.
// ---------------------------------------------------------------------------
function _x5b64ToBytes(b64) {
  const bin = atob(String(b64).replace(/[^A-Za-z0-9+/=]/g, ''));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function _x5pemToDer(pem) {
  const m = /-----BEGIN [^-]+-----([\s\S]*?)-----END [^-]+-----/.exec(pem);
  return _x5b64ToBytes(m ? m[1] : pem);
}
function _x5node(b, pos) {
  const start = pos; let first = b[pos++];
  const cls = first >> 6, constructed = (first & 0x20) !== 0; let tag = first & 0x1f;
  if (tag === 0x1f) { tag = 0; let c; do { c = b[pos++]; tag = tag * 128 + (c & 0x7f); } while (c & 0x80); }
  let len = b[pos++], length;
  if (len < 0x80) length = len;
  else { const n = len & 0x7f; length = 0; for (let i = 0; i < n; i++) length = length * 256 + b[pos++]; }
  return { cls, constructed, tag, start, contentStart: pos, contentEnd: pos + length, end: pos + length };
}
function _x5children(b, node) {
  const out = []; let p = node.contentStart;
  while (p < node.contentEnd) { const c = _x5node(b, p); out.push(c); if (c.end <= p) break; p = c.end; }
  return out;
}
function _x5oid(b, node) {
  let p = node.contentStart; const end = node.contentEnd;
  if (p >= end) return '';
  const first = b[p++]; let s = Math.floor(first / 40) + '.' + (first % 40), v = 0;
  while (p < end) { const c = b[p++]; v = v * 128 + (c & 0x7f); if (!(c & 0x80)) { s += '.' + v; v = 0; } }
  return s;
}
function _x5strBytes(b, start, end) {
  try { return new TextDecoder('utf-8').decode(b.subarray(start, end)); }
  catch (e) { let s = ''; for (let i = start; i < end; i++) s += String.fromCharCode(b[i]); return s; }
}
function _x5hex(b, start, end) {
  let s = '';
  for (let i = start; i < end; i++) { let h = b[i].toString(16); if (h.length < 2) h = '0' + h; s += (s ? ':' : '') + h.toUpperCase(); }
  return s;
}
const _X5_DN = { '2.5.4.3':'CN','2.5.4.6':'C','2.5.4.7':'L','2.5.4.8':'ST','2.5.4.10':'O','2.5.4.11':'OU','2.5.4.5':'serialNumber','1.2.840.113549.1.9.1':'E','2.5.4.4':'SN','2.5.4.42':'GN','0.9.2342.19200300.100.1.25':'DC' };
function _x5dn(b, nameNode) {
  const out = {}, rdns = _x5children(b, nameNode);
  for (let i = 0; i < rdns.length; i++) {
    const atvs = _x5children(b, rdns[i]);
    for (let j = 0; j < atvs.length; j++) {
      const pair = _x5children(b, atvs[j]);
      if (pair.length < 2) continue;
      const oid = _x5oid(b, pair[0]);
      out[_X5_DN[oid] || oid] = _x5strBytes(b, pair[1].contentStart, pair[1].contentEnd);
    }
  }
  return out;
}
function _x5dnStr(dn) {
  const order = ['CN','OU','O','L','ST','C','E'], parts = [];
  for (let i = 0; i < order.length; i++) if (dn[order[i]]) parts.push(order[i] + '=' + dn[order[i]]);
  Object.keys(dn).forEach(function(k) { if (order.indexOf(k) === -1) parts.push(k + '=' + dn[k]); });
  return parts.join(', ');
}
function _x5time(b, node) {
  const s = _x5strBytes(b, node.contentStart, node.contentEnd); let m;
  if (node.tag === 23) {
    m = /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s);
    if (!m) return null;
    const yy = parseInt(m[1], 10), year = yy < 50 ? 2000 + yy : 1900 + yy;
    return new Date(Date.UTC(year, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
  }
  m = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?/.exec(s);
  if (!m) return null;
  return new Date(Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0)));
}
const _X5_EC = { '1.2.840.10045.3.1.7':256,'1.3.132.0.34':384,'1.3.132.0.35':521,'1.3.132.0.33':224 };
const _X5_EKU = { '1.3.6.1.5.5.7.3.1':'TLS Web Server Authentication','1.3.6.1.5.5.7.3.2':'TLS Web Client Authentication','1.3.6.1.5.5.7.3.3':'Code Signing','1.3.6.1.5.5.7.3.4':'Email Protection','1.3.6.1.5.5.7.3.8':'Time Stamping','1.3.6.1.5.5.7.3.9':'OCSP Signing' };
const _X5_KU = ['Digital Signature','Non-Repudiation','Key Encipherment','Data Encipherment','Key Agreement','Certificate Signing','CRL Signing','Encipher Only','Decipher Only'];
// OpenSSL-style names so SC_ALGOS scoring keys line up with real signature OIDs.
const SC_OID = {
  '1.2.840.113549.1.1.11':'sha256WithRSAEncryption','1.2.840.113549.1.1.12':'sha384WithRSAEncryption',
  '1.2.840.113549.1.1.13':'sha512WithRSAEncryption','1.2.840.113549.1.1.5':'sha1WithRSAEncryption',
  '1.2.840.113549.1.1.4':'md5WithRSAEncryption','1.2.840.113549.1.1.10':'RSASSA-PSS',
  '1.2.840.10045.4.3.2':'ecdsa-with-SHA256','1.2.840.10045.4.3.3':'ecdsa-with-SHA384',
  '1.2.840.10045.4.3.4':'ecdsa-with-SHA512','1.3.101.112':'Ed25519','1.3.101.113':'Ed448'
};

function _x5pubkey(der, spkiNode) {
  const spki = _x5children(der, spkiNode);
  const keyAlg = _x5children(der, spki[0]);
  const keyOid = _x5oid(der, keyAlg[0]);
  let keyType = 'Unknown', keySize = 0; const bitStr = spki[1];
  if (keyOid === '1.2.840.113549.1.1.1') {
    keyType = 'RSA';
    try { const seq = _x5node(der, bitStr.contentStart + 1); const mod = _x5children(der, seq)[0]; let ms = mod.contentStart; const me = mod.contentEnd; while (ms < me && der[ms] === 0) ms++; keySize = (me - ms) * 8; } catch (e) {}
  } else if (keyOid === '1.2.840.10045.2.1') { keyType = 'EC'; keySize = keyAlg[1] ? (_X5_EC[_x5oid(der, keyAlg[1])] || 0) : 0; }
  else if (keyOid === '1.3.101.112') { keyType = 'Ed25519'; keySize = 256; }
  else if (keyOid === '1.3.101.113') { keyType = 'Ed448'; keySize = 456; }
  return { keyType, keySize, keyOid };
}

// Parse a SEQUENCE OF Extension (works for cert extensions and CSR extensionRequest).
function _x5extensions(der, extsSeq) {
  const res = { sans: [], keyUsage: [], extKeyUsage: [], basicCA: false, crl: [], ocsp: [], caIssuers: [], hasSCT: false };
  if (!extsSeq) return res;
  const exts = _x5children(der, extsSeq);
  for (let e = 0; e < exts.length; e++) {
    const ec = _x5children(der, exts[e]);
    if (!ec.length) continue;
    const eoid = _x5oid(der, ec[0]);
    const octet = ec[ec.length - 1], vstart = octet.contentStart;
    try {
      if (eoid === '2.5.29.17') {
        const gn = _x5children(der, _x5node(der, vstart));
        for (let g = 0; g < gn.length; g++) {
          const nn = gn[g];
          if (nn.tag === 2 || nn.tag === 1) res.sans.push(_x5strBytes(der, nn.contentStart, nn.contentEnd));
          else if (nn.tag === 7 && (nn.contentEnd - nn.contentStart) === 4) res.sans.push([der[nn.contentStart], der[nn.contentStart + 1], der[nn.contentStart + 2], der[nn.contentStart + 3]].join('.'));
        }
      } else if (eoid === '2.5.29.37') {
        const eks = _x5children(der, _x5node(der, vstart));
        for (let x = 0; x < eks.length; x++) { const eo = _x5oid(der, eks[x]); res.extKeyUsage.push(_X5_EKU[eo] || eo); }
      } else if (eoid === '2.5.29.15') {
        const kuNode = _x5node(der, vstart), kb = kuNode.contentStart + 1;
        for (let bidx = 0; bidx < _X5_KU.length; bidx++) { const byteI = kb + (bidx >> 3); if (byteI >= kuNode.contentEnd) break; if ((der[byteI] >> (7 - (bidx & 7))) & 1) res.keyUsage.push(_X5_KU[bidx]); }
      } else if (eoid === '2.5.29.19') {
        const bc = _x5children(der, _x5node(der, vstart));
        for (let y = 0; y < bc.length; y++) if (bc[y].tag === 1) res.basicCA = der[bc[y].contentStart] !== 0;
      } else if (eoid === '2.5.29.31') {
        _x5collectURIs(der, _x5node(der, vstart), res.crl);
      } else if (eoid === '1.3.6.1.5.5.7.1.1') {
        const ads = _x5children(der, _x5node(der, vstart));
        for (let q = 0; q < ads.length; q++) { const adp = _x5children(der, ads[q]); if (adp.length < 2) continue; const am = _x5oid(der, adp[0]); const lu = _x5strBytes(der, adp[1].contentStart, adp[1].contentEnd); if (am === '1.3.6.1.5.5.7.48.1') res.ocsp.push(lu); else if (am === '1.3.6.1.5.5.7.48.2') res.caIssuers.push(lu); }
      } else if (eoid === '1.3.6.1.4.1.11129.2.4.2') { res.hasSCT = true; }
    } catch (ePerExt) {}
  }
  return res;
}
function _x5collectURIs(b, node, out) {
  if (node.constructed) { const ch = _x5children(b, node); for (let i = 0; i < ch.length; i++) _x5collectURIs(b, ch[i], out); }
  else if (node.tag === 22 || (node.cls === 2 && node.tag === 6)) { const u = _x5strBytes(b, node.contentStart, node.contentEnd); if (/^(https?|ldap):/.test(u)) out.push(u); }
}

function scScore(cert) {
  let score = 0;
  const algoInfo = SC_ALGOS[cert.sigAlgo] || { score: 5 };
  score += algoInfo.score * 2;
  if (cert.keyType === 'RSA') score += (SC_KEY_SCORES[cert.keySize] || 5) * 2;
  else if (cert.keyType === 'ECDSA') score += (SC_ECC_SCORES[cert.keySize] || 7) * 2;
  else score += 20;
  if (cert.daysLeft > 90) score += 20;
  else if (cert.daysLeft > 30) score += 15;
  else if (cert.daysLeft > 0) score += 5;
  if (cert.sans.length > 1) score += 10; else score += 5;
  if (cert.sigAlgo !== 'sha1WithRSAEncryption' && cert.sigAlgo !== 'md5WithRSAEncryption') score += 10;
  return Math.min(100, Math.max(0, score));
}

// Decode a single PEM certificate into the shape renderCertResult expects.
function scDecodeCert(pem) {
  const der = _x5pemToDer(pem);
  const cert = _x5node(der, 0), top = _x5children(der, cert);
  const tbs = top[0], sigAlgNode = top[1];
  const tc = _x5children(der, tbs);
  let idx = 0;
  if (tc[0] && tc[0].cls === 2 && tc[0].tag === 0) idx = 1;
  const serialNode = tc[idx++]; idx++; // skip tbs signature alg
  const issuerNode = tc[idx++], validityNode = tc[idx++], subjectNode = tc[idx++], spkiNode = tc[idx++];
  let extNode = null;
  for (let k = idx; k < tc.length; k++) { if (tc[k].cls === 2 && tc[k].tag === 3) { extNode = tc[k]; break; } }

  const validity = _x5children(der, validityNode);
  const notBefore = validity[0] ? _x5time(der, validity[0]) : null;
  const notAfter = validity[1] ? _x5time(der, validity[1]) : null;
  const daysLeft = notAfter ? Math.floor((notAfter.getTime() - Date.now()) / 86400000) : 0;
  const sigOid = _x5oid(der, _x5children(der, sigAlgNode)[0]);
  const sigKey = SC_OID[sigOid] || sigOid;
  const pk = _x5pubkey(der, spkiNode);
  const keyType = pk.keyType === 'EC' ? 'ECDSA' : pk.keyType;
  const ext = extNode ? _x5extensions(der, _x5children(der, extNode)[0]) : { sans: [], keyUsage: [], extKeyUsage: [], basicCA: false, crl: [], ocsp: [], caIssuers: [], hasSCT: false };

  const cert2 = {
    subject: _x5dnStr(_x5dn(der, subjectNode)) || '(empty subject)',
    issuer: _x5dnStr(_x5dn(der, issuerNode)) || '(empty issuer)',
    serial: _x5hex(der, serialNode.contentStart, serialNode.contentEnd),
    notBefore: notBefore || new Date(0), notAfter: notAfter || new Date(0), daysLeft,
    sigAlgo: sigKey,
    sigAlgoInfo: SC_ALGOS[sigKey] || { name: sigKey, strength: 'Unknown', score: 5 },
    keyType, keySize: pk.keySize,
    sans: ext.sans,
    extensions: {
      keyUsage: ext.keyUsage.length ? ext.keyUsage : ['(none specified)'],
      extKeyUsage: ext.extKeyUsage.length ? ext.extKeyUsage : ['(none specified)'],
      basicConstraints: ext.basicCA ? 'CA:TRUE' : 'CA:FALSE',
      crlDistPoints: ext.crl.length ? ext.crl.join(', ') : 'Not present',
      ocsp: ext.ocsp.length ? ext.ocsp.join(', ') : 'Not present',
      authorityInfo: ext.caIssuers.length ? ext.caIssuers.join(', ') : 'Not present',
      ct: ext.hasSCT ? 'Embedded SCTs present' : 'Not present in certificate'
    },
    pem: pem.trim()
  };
  cert2.score = scScore(cert2);
  return cert2;
}

// Decode a PEM PKCS#10 CSR for its real subject, key and requested SANs.
function scParseCSRReal(csrText) {
  const der = _x5pemToDer(csrText);
  const req = _x5node(der, 0), top = _x5children(der, req);
  const cri = top[0], sigAlgNode = top[1];
  const cric = _x5children(der, cri);
  const subjectNode = cric[1], spkiNode = cric[2];
  const subject = _x5dnStr(_x5dn(der, subjectNode)) || '(empty subject)';
  const pk = _x5pubkey(der, spkiNode);
  const keyType = pk.keyType === 'EC' ? 'ECDSA' : pk.keyType;
  const sigOid = _x5oid(der, _x5children(der, sigAlgNode)[0]);
  const sigKey = SC_OID[sigOid] || sigOid;
  let sans = [], challenge = 'none';
  for (let a = 3; a < cric.length; a++) {
    const attrsCtx = cric[a];
    if (!(attrsCtx.cls === 2 && attrsCtx.tag === 0)) continue;
    const attrs = _x5children(der, attrsCtx);
    for (let i = 0; i < attrs.length; i++) {
      const ac = _x5children(der, attrs[i]);
      if (ac.length < 2) continue;
      const aoid = _x5oid(der, ac[0]);
      if (aoid === '1.2.840.113549.1.9.14') { const setItems = _x5children(der, ac[1]); if (setItems[0]) sans = _x5extensions(der, setItems[0]).sans; }
      else if (aoid === '1.2.840.113549.1.9.7') { const cp = _x5children(der, ac[1])[0]; if (cp) challenge = _x5strBytes(der, cp.contentStart, cp.contentEnd); }
    }
  }
  return {
    subject, keyType, keySize: pk.keySize,
    sigAlgo: SC_ALGOS[sigKey] ? SC_ALGOS[sigKey].name : sigKey,
    sans, challengePassword: challenge, valid: true
  };
}

// Fetch the newest leaf certificate for a hostname from crt.sh (CT logs) via the proxy.
async function scCtFetchPEM(host) {
  if (!proxyConfigured()) throw new Error('The Darknode proxy is not configured, so certificates cannot be fetched from CT logs.');
  const list = await dnFetch('https://crt.sh/?q=' + encodeURIComponent(host) + '&output=json&exclude=expired', { raw: true, timeout: 15000 });
  let arr; try { arr = JSON.parse(list.body); } catch (e) { throw new Error('crt.sh returned no parseable data for ' + host + '.'); }
  if (!Array.isArray(arr) || !arr.length) throw new Error('No certificates found in CT logs for ' + host + '.');
  arr.sort(function(a, b) { return (b.id || 0) - (a.id || 0); });
  const pem = await dnFetch('https://crt.sh/?d=' + encodeURIComponent(arr[0].id), { raw: true, timeout: 15000 });
  if (!/BEGIN CERTIFICATE/.test(pem.body || '')) throw new Error('Could not download the certificate PEM from crt.sh.');
  return pem.body;
}

export function renderSSLCertAnalyzer(container) {
  let activeTab = 'decode';

  const style = document.createElement('style');
  style.textContent = `
    .sc-wrap{background:#0a0e14;color:#c8d6e5;font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;padding:0}
    .sc-header{background:linear-gradient(135deg,#0c1220 0%,#0f1a2e 50%,#0a1628 100%);padding:20px 28px;border-bottom:1px solid #1a2a44}
    .sc-header h2{margin:0;font-size:22px;font-weight:700;color:#00aaff;letter-spacing:1px;display:flex;align-items:center;gap:10px}
    .sc-header h2 svg{width:24px;height:24px;fill:#00aaff}
    .sc-subtitle{margin:4px 0 0;font-size:13px;color:#6a8aaa;font-weight:400}
    .sc-tabs{display:flex;gap:0;background:#0c1220;border-bottom:1px solid #1a2a44;padding:0 20px;overflow-x:auto}
    .sc-tab{padding:12px 20px;background:none;border:none;color:#6a8aaa;font-size:13px;cursor:pointer;border-bottom:2px solid transparent;transition:all .2s;white-space:nowrap;font-family:inherit}
    .sc-tab:hover{color:#c8d6e5;background:rgba(0,170,255,0.05)}
    .sc-tab.active{color:#00aaff;border-bottom-color:#00aaff;background:rgba(0,170,255,0.08)}
    .sc-content{padding:24px 28px}
    .sc-panel{background:#0c1220;border:1px solid #1a2a44;border-radius:8px;padding:20px;margin-bottom:16px}
    .sc-panel h3{margin:0 0 14px;font-size:15px;color:#00aaff;font-weight:600}
    .sc-textarea{width:100%;min-height:160px;background:#080c14;border:1px solid #1a2a44;border-radius:6px;color:#c8d6e5;padding:12px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;resize:vertical;box-sizing:border-box}
    .sc-textarea:focus{outline:none;border-color:#00aaff;box-shadow:0 0 0 2px rgba(0,170,255,0.15)}
    .sc-textarea::placeholder{color:#3a5a7a}
    .sc-btn{padding:10px 22px;background:#00aaff;color:#0a0e14;border:none;border-radius:4px;font-weight:600;font-size:13px;cursor:pointer;transition:all .2s;font-family:inherit}
    .sc-btn:hover{background:#0088dd;transform:translateY(-1px)}
    .sc-btn.secondary{background:transparent;border:1px solid #1a2a44;color:#c8d6e5}
    .sc-btn.secondary:hover{border-color:#00aaff;color:#00aaff}
    .sc-btn-row{display:flex;gap:10px;margin:14px 0}
    .sc-field{display:grid;grid-template-columns:180px 1fr;gap:0;border-bottom:1px solid #111a2e;padding:10px 0;align-items:start}
    .sc-field:last-child{border-bottom:none}
    .sc-field-label{color:#6a8aaa;font-size:12px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;padding-top:2px}
    .sc-field-value{color:#e2e8f0;font-size:13px;word-break:break-all}
    .sc-badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:11px;font-weight:600;letter-spacing:.5px}
    .sc-badge.green{background:rgba(0,255,136,0.12);color:#00ff88}
    .sc-badge.yellow{background:rgba(255,214,0,0.12);color:#ffd600}
    .sc-badge.red{background:rgba(255,68,68,0.12);color:#ff4444}
    .sc-badge.blue{background:rgba(0,170,255,0.12);color:#00aaff}
    .sc-badge.purple{background:rgba(167,139,250,0.12);color:#a78bfa}
    .sc-grade-box{display:flex;align-items:center;gap:20px;padding:20px;border-radius:8px;margin-bottom:16px}
    .sc-grade-letter{font-size:56px;font-weight:800;line-height:1}
    .sc-grade-info{flex:1}
    .sc-grade-label{font-size:12px;color:#6a8aaa;text-transform:uppercase;letter-spacing:1px;margin-bottom:4px}
    .sc-grade-score{font-size:20px;font-weight:700;color:#e2e8f0}
    .sc-bar{height:6px;background:#111a2e;border-radius:3px;margin-top:8px;overflow:hidden}
    .sc-bar-fill{height:100%;border-radius:3px;transition:width .6s ease}
    .sc-expiry{display:flex;align-items:center;gap:12px;padding:14px 18px;border-radius:8px;margin:12px 0}
    .sc-expiry-days{font-size:28px;font-weight:800;line-height:1}
    .sc-expiry-label{font-size:12px;color:#6a8aaa}
    .sc-san-list{display:flex;flex-wrap:wrap;gap:6px}
    .sc-san-item{background:#111a2e;padding:4px 12px;border-radius:4px;font-size:12px;color:#c8d6e5;border:1px solid #1a2a44;font-family:monospace}
    .sc-ext-row{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;border-bottom:1px solid #111a2e}
    .sc-ext-row:last-child{border-bottom:none}
    .sc-ext-name{color:#6a8aaa;font-size:12px;font-weight:600}
    .sc-ext-val{color:#c8d6e5;font-size:12px;text-align:right;max-width:60%;word-break:break-all}
    .sc-chain{display:flex;flex-direction:column;gap:0}
    .sc-chain-cert{position:relative;padding:16px 20px;background:#0c1220;border:1px solid #1a2a44;border-radius:8px;margin-left:20px}
    .sc-chain-cert::before{content:'';position:absolute;left:-16px;top:0;bottom:-16px;width:2px;background:#1a2a44}
    .sc-chain-cert::after{content:'';position:absolute;left:-16px;top:24px;width:12px;height:2px;background:#1a2a44}
    .sc-chain-cert:last-child::before{bottom:50%}
    .sc-chain-connector{text-align:center;padding:6px 0;color:#3a5a7a;font-size:18px;margin-left:20px}
    .sc-chain-level{position:absolute;left:-60px;top:20px;font-size:10px;color:#3a5a7a;text-transform:uppercase;letter-spacing:1px;writing-mode:vertical-rl;transform:rotate(180deg)}
    .sc-form-group{margin-bottom:16px}
    .sc-form-group label{display:block;font-size:12px;color:#6a8aaa;margin-bottom:6px;font-weight:600;text-transform:uppercase;letter-spacing:.5px}
    .sc-input{width:100%;padding:10px 14px;background:#080c14;border:1px solid #1a2a44;border-radius:6px;color:#c8d6e5;font-size:13px;box-sizing:border-box;font-family:inherit}
    .sc-input:focus{outline:none;border-color:#00aaff}
    .sc-select{width:100%;padding:10px 14px;background:#080c14;border:1px solid #1a2a44;border-radius:6px;color:#c8d6e5;font-size:13px;box-sizing:border-box;font-family:inherit}
    .sc-grid-2{display:grid;grid-template-columns:1fr 1fr;gap:16px}
    .sc-code{background:#080c14;border:1px solid #1a2a44;border-radius:6px;padding:14px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#c8d6e5;white-space:pre-wrap;overflow-x:auto;position:relative}
    .sc-code .sc-copy-btn{position:absolute;top:8px;right:8px;padding:4px 10px;background:#1a2a44;border:none;color:#6a8aaa;border-radius:4px;cursor:pointer;font-size:11px}
    .sc-code .sc-copy-btn:hover{color:#00aaff;background:#223355}
    .sc-ref-card{background:#0c1220;border:1px solid #1a2a44;border-radius:8px;padding:16px;margin-bottom:12px}
    .sc-ref-card h4{margin:0 0 8px;color:#00aaff;font-size:14px}
    .sc-ref-card p{margin:0 0 8px;color:#8ab4d8;font-size:13px;line-height:1.5}
    .sc-ref-card code{background:#080c14;padding:2px 8px;border-radius:3px;font-size:12px;color:#00ff88}
    .sc-empty{text-align:center;padding:40px;color:#3a5a7a;font-size:14px}
    .sc-result-section{margin-top:20px}
    .sc-table{width:100%;border-collapse:collapse}
    .sc-table th{text-align:left;padding:8px 12px;background:#080c14;color:#6a8aaa;font-size:11px;text-transform:uppercase;letter-spacing:.5px;border-bottom:2px solid #1a2a44}
    .sc-table td{padding:8px 12px;border-bottom:1px solid #111a2e;font-size:13px;color:#c8d6e5}
    @media(max-width:768px){
      .sc-grid-2{grid-template-columns:1fr}
      .sc-field{grid-template-columns:1fr;gap:4px}
      .sc-content{padding:16px}
      .sc-grade-letter{font-size:40px}
    }
  `;
  document.head.appendChild(style);

  function renderDecode() {
    const cliReady = window._bridge && window._bridge.connected && window._bridge.hasTool('openssl');
    return `
      <div class="sc-panel">
        <div style="margin-bottom:12px"><label style="font-size:12px;opacity:.7">Fetch a live certificate by hostname${cliReady ? ' (CLI openssl connected)' : ' (via Darknode proxy + crt.sh CT logs)'}</label><div style="display:flex;gap:8px;margin-top:4px"><input class="sc-textarea" id="sc-domain-input" style="height:36px;font-size:13px" placeholder="example.com"><button class="sc-btn" id="sc-fetch-btn" style="white-space:nowrap">Fetch Certificate</button></div></div>
        <div style="text-align:center;padding:6px 0;font-size:11px;opacity:.5">or paste manually</div>
        <h3>Paste PEM Certificate</h3>
        <textarea class="sc-textarea" id="sc-pem-input" placeholder="-----BEGIN CERTIFICATE-----\nMIIFazCCBFOgAwIBAgISA...\n-----END CERTIFICATE-----"></textarea>
        <div class="sc-btn-row">
          <button class="sc-btn" id="sc-decode-btn">Decode Certificate</button>
          <button class="sc-btn secondary" id="sc-export-btn" style="display:none">Export JSON</button>
        </div>
      </div>
      <div id="sc-decode-result"></div>
    `;
  }

  function renderCertResult(cert) {
    const g = scGrade(cert.score);
    const expiryColor = cert.daysLeft > 90 ? '#00ff88' : cert.daysLeft > 30 ? '#ffd600' : '#ff4444';
    const expiryBg = cert.daysLeft > 90 ? 'rgba(0,255,136,0.08)' : cert.daysLeft > 30 ? 'rgba(255,214,0,0.08)' : 'rgba(255,68,68,0.08)';
    const expiryLabel = cert.daysLeft > 90 ? 'Healthy' : cert.daysLeft > 30 ? 'Expiring Soon' : cert.daysLeft > 0 ? 'Critical' : 'Expired';

    return `
      <div class="sc-grade-box" style="background:${g.bg};border:1px solid ${g.color}30">
        <div class="sc-grade-letter" style="color:${g.color}">${g.grade}</div>
        <div class="sc-grade-info">
          <div class="sc-grade-label">Security Rating</div>
          <div class="sc-grade-score">${cert.score}/100</div>
          <div class="sc-bar"><div class="sc-bar-fill" style="width:${cert.score}%;background:${g.color}"></div></div>
        </div>
      </div>

      <div class="sc-expiry" style="background:${expiryBg};border:1px solid ${expiryColor}30">
        <div class="sc-expiry-days" style="color:${expiryColor}">${cert.daysLeft > 0 ? cert.daysLeft : 'EXPIRED'}</div>
        <div>
          <div style="color:${expiryColor};font-weight:600;font-size:13px">${cert.daysLeft > 0 ? 'Days Until Expiration' : 'Certificate Has Expired'}</div>
          <div class="sc-expiry-label">${expiryLabel} &mdash; Expires ${cert.notAfter.toLocaleDateString()}</div>
        </div>
      </div>

      <div class="sc-panel">
        <h3>Certificate Details</h3>
        <div class="sc-field"><span class="sc-field-label">Subject</span><span class="sc-field-value">${esc(cert.subject)}</span></div>
        <div class="sc-field"><span class="sc-field-label">Issuer</span><span class="sc-field-value">${esc(cert.issuer)}</span></div>
        <div class="sc-field"><span class="sc-field-label">Serial Number</span><span class="sc-field-value" style="font-family:monospace">${esc(cert.serial)}</span></div>
        <div class="sc-field"><span class="sc-field-label">Valid From</span><span class="sc-field-value">${cert.notBefore.toISOString()}</span></div>
        <div class="sc-field"><span class="sc-field-label">Valid To</span><span class="sc-field-value">${cert.notAfter.toISOString()}</span></div>
        <div class="sc-field"><span class="sc-field-label">Signature Algorithm</span><span class="sc-field-value">${esc(cert.sigAlgoInfo.name)} <span class="sc-badge ${cert.sigAlgoInfo.strength === 'Strong' ? 'green' : cert.sigAlgoInfo.strength === 'Weak' ? 'yellow' : 'red'}">${cert.sigAlgoInfo.strength}</span></span></div>
        <div class="sc-field"><span class="sc-field-label">Public Key</span><span class="sc-field-value">${esc(cert.keyType)} ${cert.keySize}-bit</span></div>
        <div class="sc-field">
          <span class="sc-field-label">Subject Alt Names</span>
          <span class="sc-field-value"><div class="sc-san-list">${cert.sans.map(s => `<span class="sc-san-item">${esc(s)}</span>`).join('')}</div></span>
        </div>
      </div>

      <div class="sc-panel">
        <h3>Extensions</h3>
        <div class="sc-ext-row"><span class="sc-ext-name">Key Usage</span><span class="sc-ext-val">${cert.extensions.keyUsage.join(', ')}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">Extended Key Usage</span><span class="sc-ext-val">${cert.extensions.extKeyUsage.join(', ')}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">Basic Constraints</span><span class="sc-ext-val">${cert.extensions.basicConstraints}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">CRL Distribution</span><span class="sc-ext-val">${esc(cert.extensions.crlDistPoints)}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">OCSP Responder</span><span class="sc-ext-val">${esc(cert.extensions.ocsp)}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">Authority Info</span><span class="sc-ext-val">${esc(cert.extensions.authorityInfo)}</span></div>
        <div class="sc-ext-row"><span class="sc-ext-name">CT Precertificate</span><span class="sc-ext-val">${cert.extensions.ct}</span></div>
      </div>

      <div class="sc-panel">
        <h3>Score Breakdown</h3>
        <table class="sc-table">
          <thead><tr><th>Category</th><th>Score</th><th>Details</th></tr></thead>
          <tbody>
            <tr><td>Signature Algorithm</td><td>${cert.sigAlgoInfo.score * 2}/20</td><td>${esc(cert.sigAlgoInfo.name)}</td></tr>
            <tr><td>Key Strength</td><td>${cert.keyType === 'RSA' ? (SC_KEY_SCORES[cert.keySize] || 5) * 2 : cert.keyType === 'ECDSA' ? (SC_ECC_SCORES[cert.keySize] || 7) * 2 : 20}/20</td><td>${cert.keyType} ${cert.keySize}-bit</td></tr>
            <tr><td>Validity Period</td><td>${cert.daysLeft > 90 ? 20 : cert.daysLeft > 30 ? 15 : cert.daysLeft > 0 ? 5 : 0}/20</td><td>${cert.daysLeft} days remaining</td></tr>
            <tr><td>SAN Coverage</td><td>${cert.sans.length > 1 ? 10 : 5}/10</td><td>${cert.sans.length} name(s)</td></tr>
            <tr><td>Modern Standards</td><td>${cert.sigAlgo !== 'sha1WithRSAEncryption' && cert.sigAlgo !== 'md5WithRSAEncryption' ? 10 : 0}/10</td><td>${cert.sigAlgo !== 'sha1WithRSAEncryption' && cert.sigAlgo !== 'md5WithRSAEncryption' ? 'Compliant' : 'Deprecated algorithm'}</td></tr>
          </tbody>
        </table>
      </div>
    `;
  }

  function renderChain() {
    return `
      <div class="sc-panel">
        <h3>Certificate Chain Validator</h3>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Paste the full PEM chain (multiple certificates). The tool will analyze the chain of trust from end-entity to root CA.</p>
        <textarea class="sc-textarea" id="sc-chain-input" style="min-height:200px" placeholder="-----BEGIN CERTIFICATE-----\n(End-entity certificate)\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n(Intermediate CA)\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n(Root CA)\n-----END CERTIFICATE-----"></textarea>
        <div class="sc-btn-row">
          <button class="sc-btn" id="sc-chain-btn">Validate Chain</button>
        </div>
      </div>
      <div id="sc-chain-result"></div>
    `;
  }

  function cnOf(dnStr) {
    const m = /CN=([^,]+)/.exec(dnStr || '');
    return m ? m[1].trim() : (dnStr ? dnStr.split(',')[0] : 'Unknown');
  }

  function renderChainResult(pems) {
    const certs = pems.map(p => scDecodeCert(p));
    // Real level: a cert whose issuer equals its own subject is a (self-signed) root.
    let html = '<div class="sc-panel"><h3>Chain Analysis</h3>';
    html += `<div style="margin-bottom:12px"><span class="sc-badge ${certs.length >= 2 ? 'green' : 'yellow'}">${certs.length} certificate(s) in chain</span></div>`;
    html += '<div class="sc-chain">';
    certs.forEach((cert, i) => {
      const selfSigned = cert.subject === cert.issuer;
      const level = selfSigned ? 'Root CA' : (i === 0 ? 'End-Entity' : 'Intermediate CA');
      const isRoot = level === 'Root CA';
      const g = scGrade(cert.score);
      html += `
        <div class="sc-chain-cert" style="margin-left:${i * 24 + 20}px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span class="sc-badge ${isRoot ? 'purple' : i === 0 ? 'blue' : 'green'}">${esc(level)}</span>
            <span class="sc-badge" style="background:${g.bg};color:${g.color}">${g.grade} (${cert.score}/100)</span>
          </div>
          <div style="font-size:13px;color:#e2e8f0;margin-bottom:4px;font-weight:600">${esc(cnOf(cert.subject))}</div>
          <div style="font-size:12px;color:#6a8aaa">Issuer: ${esc(cnOf(cert.issuer))}</div>
          <div style="font-size:12px;color:#6a8aaa">${esc(cert.keyType)} ${cert.keySize}-bit &bull; ${esc(cert.sigAlgoInfo.name)}</div>
          <div style="font-size:12px;color:${cert.daysLeft > 90 ? '#00ff88' : cert.daysLeft > 30 ? '#ffd600' : '#ff4444'}">${cert.daysLeft > 0 ? cert.daysLeft + ' days remaining' : 'EXPIRED'}</div>
        </div>
      `;
      if (i < certs.length - 1) {
        html += `<div class="sc-chain-connector" style="margin-left:${i * 24 + 36}px">&#x2193; signed by</div>`;
      }
    });
    html += '</div>';
    // Verify each cert's issuer matches the next cert's subject (real linkage check).
    let linkOk = certs.length >= 2;
    for (let i = 0; i < certs.length - 1; i++) { if (certs[i].issuer !== certs[i + 1].subject) linkOk = false; }
    const multi = certs.length >= 2;
    html += `<div style="margin-top:16px;padding:12px 16px;border-radius:6px;background:${linkOk ? 'rgba(0,255,136,0.08)' : 'rgba(255,214,0,0.08)'};border:1px solid ${linkOk ? '#00ff8830' : '#ffd60030'}">
      <span style="color:${linkOk ? '#00ff88' : '#ffd600'};font-weight:600">${!multi ? '&#x26A0; Single certificate — no chain to validate' : linkOk ? '&#x2713; Each issuer matches the next subject' : '&#x26A0; Chain order gap: an issuer does not match the next certificate subject'}</span>
      <div style="color:#6a8aaa;font-size:12px;margin-top:4px">${multi ? `Trust path: ${certs.map(c => esc(cnOf(c.subject))).join(' &rarr; ')}` : 'Paste the full PEM chain (leaf + intermediates + root) to validate the chain of trust.'}</div>
    </div>`;
    html += '</div>';
    return html;
  }

  function renderCSR() {
    return `
      <div class="sc-panel">
        <h3>CSR Decoder</h3>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 14px">Paste a PEM-encoded Certificate Signing Request to decode its contents.</p>
        <textarea class="sc-textarea" id="sc-csr-input" placeholder="-----BEGIN CERTIFICATE REQUEST-----\nMIICYjCCAUoCAQAwHTELMA...\n-----END CERTIFICATE REQUEST-----"></textarea>
        <div class="sc-btn-row">
          <button class="sc-btn" id="sc-csr-btn">Decode CSR</button>
        </div>
      </div>
      <div id="sc-csr-result"></div>
    `;
  }

  function renderCSRResult(csr) {
    return `
      <div class="sc-panel">
        <h3>CSR Details</h3>
        <div style="margin-bottom:12px"><span class="sc-badge ${csr.valid ? 'green' : 'red'}">${csr.valid ? 'Valid CSR' : 'Invalid CSR'}</span></div>
        <div class="sc-field"><span class="sc-field-label">Subject</span><span class="sc-field-value">${esc(csr.subject)}</span></div>
        <div class="sc-field"><span class="sc-field-label">Key Type</span><span class="sc-field-value">${csr.keyType} ${csr.keySize}-bit</span></div>
        <div class="sc-field"><span class="sc-field-label">Signature Algorithm</span><span class="sc-field-value">${csr.sigAlgo}</span></div>
        <div class="sc-field"><span class="sc-field-label">Subject Alt Names</span><span class="sc-field-value"><div class="sc-san-list">${csr.sans.map(s => `<span class="sc-san-item">${esc(s)}</span>`).join('')}</div></span></div>
        <div class="sc-field"><span class="sc-field-label">Challenge Password</span><span class="sc-field-value">${csr.challengePassword}</span></div>
      </div>
    `;
  }

  function renderGenerate() {
    return `
      <div class="sc-panel">
        <h3>Self-Signed Certificate Generator</h3>
        <p style="color:#6a8aaa;font-size:13px;margin:0 0 16px">Configure parameters and generate OpenSSL commands for self-signed certificates.</p>
        <div class="sc-grid-2">
          <div class="sc-form-group">
            <label>Common Name (CN)</label>
            <input class="sc-input" id="sc-gen-cn" value="localhost" placeholder="e.g. example.com">
          </div>
          <div class="sc-form-group">
            <label>Organization (O)</label>
            <input class="sc-input" id="sc-gen-org" value="Development" placeholder="e.g. My Corp">
          </div>
          <div class="sc-form-group">
            <label>Key Algorithm</label>
            <select class="sc-select" id="sc-gen-algo">
              <option value="rsa2048">RSA 2048-bit</option>
              <option value="rsa4096">RSA 4096-bit</option>
              <option value="ec256">ECDSA P-256</option>
              <option value="ec384">ECDSA P-384</option>
              <option value="ed25519">Ed25519</option>
            </select>
          </div>
          <div class="sc-form-group">
            <label>Validity (days)</label>
            <input class="sc-input" id="sc-gen-days" type="number" value="365" min="1" max="3650">
          </div>
          <div class="sc-form-group">
            <label>Country (C)</label>
            <input class="sc-input" id="sc-gen-country" value="US" maxlength="2" placeholder="US">
          </div>
          <div class="sc-form-group">
            <label>State (ST)</label>
            <input class="sc-input" id="sc-gen-state" value="California" placeholder="e.g. California">
          </div>
        </div>
        <div class="sc-form-group">
          <label>Subject Alternative Names (comma-separated)</label>
          <input class="sc-input" id="sc-gen-sans" value="localhost,127.0.0.1" placeholder="e.g. example.com,*.example.com,192.168.1.1">
        </div>
        <div class="sc-btn-row">
          <button class="sc-btn" id="sc-gen-btn">Generate Commands</button>
        </div>
      </div>
      <div id="sc-gen-result"></div>
    `;
  }

  function renderGenResult() {
    const cn = container.querySelector('#sc-gen-cn')?.value || 'localhost';
    const org = container.querySelector('#sc-gen-org')?.value || 'Dev';
    const algo = container.querySelector('#sc-gen-algo')?.value || 'rsa2048';
    const days = container.querySelector('#sc-gen-days')?.value || '365';
    const country = container.querySelector('#sc-gen-country')?.value || 'US';
    const state = container.querySelector('#sc-gen-state')?.value || 'California';
    const sans = container.querySelector('#sc-gen-sans')?.value || cn;
    const sanEntries = sans.split(',').map(s => s.trim()).filter(Boolean);
    const sanLine = sanEntries.map(s => /^\d+\.\d+\.\d+\.\d+$/.test(s) ? `IP:${s}` : `DNS:${s}`).join(',');
    const subj = `/C=${country}/ST=${state}/O=${org}/CN=${cn}`;

    let keyCmd, certCmd;
    if (algo === 'rsa2048') {
      keyCmd = `openssl genrsa -out server.key 2048`;
      certCmd = `openssl req -new -x509 -key server.key -out server.crt -days ${days} \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;
    } else if (algo === 'rsa4096') {
      keyCmd = `openssl genrsa -out server.key 4096`;
      certCmd = `openssl req -new -x509 -key server.key -out server.crt -days ${days} \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;
    } else if (algo === 'ec256') {
      keyCmd = `openssl ecparam -genkey -name prime256v1 -out server.key`;
      certCmd = `openssl req -new -x509 -key server.key -out server.crt -days ${days} \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;
    } else if (algo === 'ec384') {
      keyCmd = `openssl ecparam -genkey -name secp384r1 -out server.key`;
      certCmd = `openssl req -new -x509 -key server.key -out server.crt -days ${days} \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;
    } else {
      keyCmd = `openssl genpkey -algorithm Ed25519 -out server.key`;
      certCmd = `openssl req -new -x509 -key server.key -out server.crt -days ${days} \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;
    }

    const csrCmd = `openssl req -new -key server.key -out server.csr \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;

    const verifyCmd = `openssl x509 -in server.crt -text -noout`;

    const oneLiners = `# One-liner: generate key + cert in one command
openssl req -x509 -newkey ${algo.startsWith('rsa') ? `rsa:${algo.replace('rsa', '')}` : algo === 'ec256' ? 'ec -pkeyopt ec_paramgen_curve:prime256v1' : algo === 'ec384' ? 'ec -pkeyopt ec_paramgen_curve:secp384r1' : 'ed25519'} \\
  -keyout server.key -out server.crt -days ${days} -nodes \\
  -subj "${subj}" \\
  -addext "subjectAltName=${sanLine}"`;

    return `
      <div class="sc-panel">
        <h3>1. Generate Private Key</h3>
        <div class="sc-code"><button class="sc-copy-btn" data-copy="key">Copy</button>${esc(keyCmd)}</div>
      </div>
      <div class="sc-panel">
        <h3>2. Generate Self-Signed Certificate</h3>
        <div class="sc-code"><button class="sc-copy-btn" data-copy="cert">Copy</button>${esc(certCmd)}</div>
      </div>
      <div class="sc-panel">
        <h3>3. Generate CSR (for CA signing)</h3>
        <div class="sc-code"><button class="sc-copy-btn" data-copy="csr">Copy</button>${esc(csrCmd)}</div>
      </div>
      <div class="sc-panel">
        <h3>4. Verify Certificate</h3>
        <div class="sc-code"><button class="sc-copy-btn" data-copy="verify">Copy</button>${esc(verifyCmd)}</div>
      </div>
      <div class="sc-panel">
        <h3>Quick One-Liner</h3>
        <div class="sc-code"><button class="sc-copy-btn" data-copy="oneliner">Copy</button>${esc(oneLiners)}</div>
      </div>
    `;
  }

  function renderReference() {
    return `
      <div class="sc-ref-card">
        <h4>Certificate Transparency (CT)</h4>
        <p>CT is an open framework for monitoring and auditing SSL/TLS certificates. All publicly-trusted CAs must log certificates to CT logs, making misissued certificates detectable.</p>
        <p><strong>CT Log Monitors:</strong></p>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-top:8px">
          <span class="sc-badge blue">crt.sh</span>
          <span class="sc-badge blue">Censys</span>
          <span class="sc-badge blue">Google Transparency Report</span>
          <span class="sc-badge blue">Facebook CT Monitor</span>
        </div>
      </div>

      <div class="sc-ref-card">
        <h4>Key Size Recommendations (NIST SP 800-57)</h4>
        <table class="sc-table">
          <thead><tr><th>Algorithm</th><th>Minimum</th><th>Recommended</th><th>Security Level</th></tr></thead>
          <tbody>
            <tr><td>RSA</td><td>2048-bit</td><td>3072+ bit</td><td>112-bit</td></tr>
            <tr><td>ECDSA</td><td>P-256</td><td>P-384</td><td>128-bit</td></tr>
            <tr><td>Ed25519</td><td>256-bit</td><td>256-bit</td><td>128-bit</td></tr>
          </tbody>
        </table>
      </div>

      <div class="sc-ref-card">
        <h4>Common OpenSSL Commands</h4>
        <div class="sc-code"># View certificate details
openssl x509 -in cert.pem -text -noout

# Check certificate expiry
openssl x509 -in cert.pem -enddate -noout

# Verify certificate chain
openssl verify -CAfile ca-bundle.crt cert.pem

# Convert PEM to DER
openssl x509 -in cert.pem -outform DER -out cert.der

# Convert DER to PEM
openssl x509 -in cert.der -inform DER -outform PEM -out cert.pem

# Extract public key
openssl x509 -in cert.pem -pubkey -noout > pubkey.pem

# Check private key
openssl rsa -in key.pem -check

# Check CSR
openssl req -in csr.pem -text -noout -verify

# Test SSL connection
openssl s_client -connect example.com:443 -servername example.com

# Get certificate from server
echo | openssl s_client -connect example.com:443 2>/dev/null | openssl x509 -text</div>
      </div>

      <div class="sc-ref-card">
        <h4>TLS Version History</h4>
        <table class="sc-table">
          <thead><tr><th>Version</th><th>Year</th><th>Status</th><th>Notes</th></tr></thead>
          <tbody>
            <tr><td>SSL 2.0</td><td>1995</td><td><span class="sc-badge red">Deprecated</span></td><td>Fundamentally broken</td></tr>
            <tr><td>SSL 3.0</td><td>1996</td><td><span class="sc-badge red">Deprecated</span></td><td>POODLE vulnerability</td></tr>
            <tr><td>TLS 1.0</td><td>1999</td><td><span class="sc-badge red">Deprecated</span></td><td>BEAST, deprecated by RFC 8996</td></tr>
            <tr><td>TLS 1.1</td><td>2006</td><td><span class="sc-badge red">Deprecated</span></td><td>Deprecated by RFC 8996</td></tr>
            <tr><td>TLS 1.2</td><td>2008</td><td><span class="sc-badge green">Active</span></td><td>Widely supported, AEAD ciphers</td></tr>
            <tr><td>TLS 1.3</td><td>2018</td><td><span class="sc-badge green">Recommended</span></td><td>Faster handshake, forward secrecy</td></tr>
          </tbody>
        </table>
      </div>

      <div class="sc-ref-card">
        <h4>Certificate Types</h4>
        <table class="sc-table">
          <thead><tr><th>Type</th><th>Validation</th><th>Use Case</th></tr></thead>
          <tbody>
            <tr><td>DV (Domain Validated)</td><td>Domain ownership only</td><td>Blogs, personal sites</td></tr>
            <tr><td>OV (Organization Validated)</td><td>Organization identity</td><td>Business websites</td></tr>
            <tr><td>EV (Extended Validation)</td><td>Thorough vetting</td><td>Banks, e-commerce</td></tr>
            <tr><td>Wildcard (*.domain)</td><td>DV or OV</td><td>Multiple subdomains</td></tr>
            <tr><td>SAN/UCC</td><td>DV, OV, or EV</td><td>Multiple domains</td></tr>
          </tbody>
        </table>
      </div>
    `;
  }

  function render() {
    container.innerHTML = `
      <div class="sc-wrap">
        <div class="sc-header">
          <h2><svg viewBox="0 0 24 24"><path d="M12 1L3 5v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V5l-9-4zm0 2.18l7 3.12v4.7c0 4.83-3.4 9.36-7 10.5-3.6-1.14-7-5.67-7-10.5V6.3l7-3.12zM11 7v2h2V7h-2zm0 4v6h2v-6h-2z"/></svg>SSL/TLS Certificate Analyzer</h2>
          <div class="sc-subtitle">Decode, validate, and analyze X.509 certificates, CSRs, and certificate chains</div>
        </div>
        <div class="sc-tabs">
          <button class="sc-tab ${activeTab === 'decode' ? 'active' : ''}" data-tab="decode">Decode</button>
          <button class="sc-tab ${activeTab === 'chain' ? 'active' : ''}" data-tab="chain">Chain</button>
          <button class="sc-tab ${activeTab === 'csr' ? 'active' : ''}" data-tab="csr">CSR</button>
          <button class="sc-tab ${activeTab === 'generate' ? 'active' : ''}" data-tab="generate">Generate</button>
          <button class="sc-tab ${activeTab === 'reference' ? 'active' : ''}" data-tab="reference">Reference</button>
        </div>
        <div class="sc-content" id="sc-tab-content">
          ${activeTab === 'decode' ? renderDecode() : activeTab === 'chain' ? renderChain() : activeTab === 'csr' ? renderCSR() : activeTab === 'generate' ? renderGenerate() : renderReference()}
        </div>
      </div>
    `;

    container.querySelectorAll('.sc-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        activeTab = tab.dataset.tab;
        render();
      });
    });

    if (activeTab === 'decode') {
      const decodeBtn = container.querySelector('#sc-decode-btn');
      const exportBtn = container.querySelector('#sc-export-btn');
      const input = container.querySelector('#sc-pem-input');
      const resultDiv = container.querySelector('#sc-decode-result');
      let lastCert = null;

      const doDecode = (pem) => {
        const certs = scParsePEM(pem);
        if (!certs.length) { resultDiv.innerHTML = '<div class="sc-empty">No valid PEM certificate blocks found.</div>'; return; }
        try {
          lastCert = scDecodeCert(certs[0]);
          resultDiv.innerHTML = renderCertResult(lastCert);
          exportBtn.style.display = '';
        } catch (e) {
          lastCert = null;
          resultDiv.innerHTML = '<div class="sc-empty">Could not parse the certificate: ' + esc((e && e.message) || 'malformed DER') + '</div>';
        }
      };

      decodeBtn?.addEventListener('click', () => {
        const pem = input.value.trim();
        if (!pem) { resultDiv.innerHTML = '<div class="sc-empty">Paste a PEM certificate above</div>'; return; }
        doDecode(pem);
      });

      const fetchBtn = container.querySelector('#sc-fetch-btn');
      const domainInput = container.querySelector('#sc-domain-input');
      if (fetchBtn && domainInput) {
        fetchBtn.addEventListener('click', async () => {
          const host = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/[/:].*/, '').replace(/[^a-zA-Z0-9.\-]/g, '');
          if (!host) return;
          const cliReady = window._bridge && window._bridge.connected && window._bridge.hasTool('openssl');
          resultDiv.innerHTML = '<div class="sc-empty">Fetching certificate for ' + esc(host) + '...</div>';
          try {
            let pem = '';
            if (cliReady) {
              const r = await window._bridge.exec('echo | openssl s_client -connect ' + host + ':443 -servername ' + host + ' 2>/dev/null | openssl x509 -outform PEM');
              if (r.stdout && r.stdout.includes('BEGIN CERTIFICATE')) pem = r.stdout;
            }
            if (!pem) pem = await scCtFetchPEM(host);
            input.value = pem;
            doDecode(pem);
          } catch (e) { resultDiv.innerHTML = '<div class="sc-empty">' + esc((e && e.message) || 'Fetch failed.') + '</div>'; }
        });
      }

      exportBtn?.addEventListener('click', () => {
        if (!lastCert) return;
        const json = JSON.stringify({
          subject: lastCert.subject,
          issuer: lastCert.issuer,
          serial: lastCert.serial,
          notBefore: lastCert.notBefore.toISOString(),
          notAfter: lastCert.notAfter.toISOString(),
          daysRemaining: lastCert.daysLeft,
          signatureAlgorithm: lastCert.sigAlgoInfo.name,
          publicKey: { type: lastCert.keyType, size: lastCert.keySize },
          subjectAltNames: lastCert.sans,
          securityScore: lastCert.score,
          grade: scGrade(lastCert.score).grade,
          extensions: lastCert.extensions
        }, null, 2);
        const blob = new Blob([json], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'certificate-analysis.json';
        a.click();
        URL.revokeObjectURL(a.href);
      });
    }

    if (activeTab === 'chain') {
      const chainBtn = container.querySelector('#sc-chain-btn');
      const chainInput = container.querySelector('#sc-chain-input');
      const chainResult = container.querySelector('#sc-chain-result');

      chainBtn?.addEventListener('click', () => {
        const pem = chainInput.value.trim();
        if (!pem) { chainResult.innerHTML = '<div class="sc-empty">Paste PEM certificates above</div>'; return; }
        const pems = scParsePEM(pem);
        if (!pems.length) { chainResult.innerHTML = '<div class="sc-empty">No valid PEM certificates found</div>'; return; }
        try { chainResult.innerHTML = renderChainResult(pems); }
        catch (e) { chainResult.innerHTML = '<div class="sc-empty">Could not parse the chain: ' + esc((e && e.message) || 'malformed DER') + '</div>'; }
      });
    }

    if (activeTab === 'csr') {
      const csrBtn = container.querySelector('#sc-csr-btn');
      const csrInput = container.querySelector('#sc-csr-input');
      const csrResult = container.querySelector('#sc-csr-result');

      csrBtn?.addEventListener('click', () => {
        const text = csrInput.value.trim();
        if (!text) { csrResult.innerHTML = '<div class="sc-empty">Paste a CSR above</div>'; return; }
        try { csrResult.innerHTML = renderCSRResult(scParseCSRReal(text)); }
        catch (e) { csrResult.innerHTML = '<div class="sc-empty">Could not parse the CSR: ' + esc((e && e.message) || 'malformed PKCS#10') + '</div>'; }
      });
    }

    if (activeTab === 'generate') {
      const genBtn = container.querySelector('#sc-gen-btn');
      const genResult = container.querySelector('#sc-gen-result');

      genBtn?.addEventListener('click', () => {
        genResult.innerHTML = renderGenResult();
        genResult.querySelectorAll('.sc-copy-btn').forEach(btn => {
          btn.addEventListener('click', () => {
            const codeEl = btn.parentElement;
            const text = codeEl.textContent.replace('Copy', '').trim();
            navigator.clipboard.writeText(text).then(() => {
              btn.textContent = 'Copied!';
              setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
            });
          });
        });
      });
    }
  }

  render();
}
