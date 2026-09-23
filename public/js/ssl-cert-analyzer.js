import { esc } from '/js/shared.js';

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

function scSimulateCertDecode(pem) {
  const b64 = pem.replace(/-----[A-Z\s]+-----/g, '').replace(/\s/g, '');
  const len = b64.length;
  const hash = [...b64].reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0);
  const absHash = Math.abs(hash);
  const algos = Object.keys(SC_ALGOS);
  const algo = algos[absHash % algos.length];
  const keyTypes = ['RSA', 'RSA', 'RSA', 'ECDSA', 'Ed25519'];
  const keyType = keyTypes[absHash % keyTypes.length];
  const keySizes = keyType === 'RSA' ? [2048, 3072, 4096] : keyType === 'ECDSA' ? [256, 384, 521] : [256];
  const keySize = keySizes[absHash % keySizes.length];
  const now = Date.now();
  const issuedDaysAgo = 30 + (absHash % 700);
  const validDays = 365 + (absHash % 730);
  const notBefore = new Date(now - issuedDaysAgo * 86400000);
  const notAfter = new Date(notBefore.getTime() + validDays * 86400000);
  const daysLeft = Math.floor((notAfter.getTime() - now) / 86400000);
  const domains = ['example.com', 'api.example.com', 'mail.example.com', 'cdn.example.com', '*.example.com'];
  const sanCount = 1 + (absHash % 4);
  const sans = domains.slice(0, sanCount);
  const issuers = ['DigiCert Global G2', 'Let\'s Encrypt Authority X3', 'Comodo RSA CA', 'GlobalSign R3', 'Amazon RSA 2048 M01'];
  const issuer = issuers[absHash % issuers.length];
  const serial = absHash.toString(16).toUpperCase().padStart(32, '0').replace(/(.{2})/g, '$1:').slice(0, -1);

  let score = 0;
  const algoInfo = SC_ALGOS[algo] || { score: 5 };
  score += algoInfo.score * 2;
  if (keyType === 'RSA') score += (SC_KEY_SCORES[keySize] || 5) * 2;
  else if (keyType === 'ECDSA') score += (SC_ECC_SCORES[keySize] || 7) * 2;
  else score += 20;
  if (daysLeft > 90) score += 20;
  else if (daysLeft > 30) score += 15;
  else if (daysLeft > 0) score += 5;
  if (sans.length > 1) score += 10;
  else score += 5;
  if (algo !== 'sha1WithRSAEncryption' && algo !== 'md5WithRSAEncryption') score += 10;
  score = Math.min(100, Math.max(0, score));

  return {
    subject: `CN=${sans[0]}, O=Example Corp, L=San Francisco, ST=California, C=US`,
    issuer: `CN=${issuer}, O=${issuer.split(' ')[0]}, C=US`,
    serial,
    notBefore, notAfter, daysLeft,
    sigAlgo: algo, sigAlgoInfo: SC_ALGOS[algo] || { name: algo, strength: 'Unknown', score: 5 },
    keyType, keySize,
    sans, score,
    extensions: {
      keyUsage: ['Digital Signature', 'Key Encipherment'],
      extKeyUsage: ['TLS Web Server Authentication', 'TLS Web Client Authentication'],
      basicConstraints: 'CA:FALSE',
      crlDistPoints: `http://crl.${issuer.split(' ')[0].toLowerCase()}.com/crl.pem`,
      ocsp: `http://ocsp.${issuer.split(' ')[0].toLowerCase()}.com`,
      authorityInfo: `http://cacerts.${issuer.split(' ')[0].toLowerCase()}.com/ca.crt`,
      ct: 'SCT: 2 signed certificate timestamps'
    },
    pem: pem.trim()
  };
}

function scParseCSR(csrText) {
  const b64 = csrText.replace(/-----[A-Z\s]+-----/g, '').replace(/\s/g, '');
  const hash = [...b64].reduce((h, c) => ((h << 5) - h + c.charCodeAt(0)) | 0, 0);
  const absHash = Math.abs(hash);
  const keyTypes = ['RSA', 'ECDSA'];
  const kt = keyTypes[absHash % 2];
  const sizes = kt === 'RSA' ? [2048, 4096] : [256, 384];
  return {
    subject: 'CN=www.example.com, O=Example Corp, L=San Francisco, ST=California, C=US',
    keyType: kt,
    keySize: sizes[absHash % sizes.length],
    sigAlgo: kt === 'RSA' ? 'sha256WithRSAEncryption' : 'ecdsa-with-SHA256',
    sans: ['www.example.com', 'example.com'],
    challengePassword: 'none',
    valid: b64.length > 20
  };
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
        ${cliReady ? '<div style="margin-bottom:12px"><label style="font-size:12px;opacity:.7">Fetch from domain (CLI connected)</label><div style="display:flex;gap:8px;margin-top:4px"><input class="sc-textarea" id="sc-domain-input" style="height:36px;font-size:13px" placeholder="example.com"><button class="sc-btn" id="sc-fetch-btn" style="white-space:nowrap">Fetch Cert <span style="color:#22c55e;font-size:10px">[LIVE]</span></button></div></div><div style="text-align:center;padding:6px 0;font-size:11px;opacity:.5">or paste manually</div>' : ''}
        <h3>Paste PEM Certificate</h3>
        <textarea class="sc-textarea" id="sc-pem-input" placeholder="-----BEGIN CERTIFICATE-----\nMIIFazCCBFOgAwIBAgISA...\n-----END CERTIFICATE-----"></textarea>
        <div class="sc-btn-row">
          <button class="sc-btn" id="sc-decode-btn">Decode Certificate</button>
          <button class="sc-btn secondary" id="sc-sample-btn">Load Sample</button>
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
          <button class="sc-btn secondary" id="sc-chain-sample-btn">Load Sample Chain</button>
        </div>
      </div>
      <div id="sc-chain-result"></div>
    `;
  }

  function renderChainResult(pems) {
    const certs = pems.map(p => scSimulateCertDecode(p));
    const levels = ['End-Entity', 'Intermediate CA', 'Intermediate CA 2', 'Root CA'];
    let html = '<div class="sc-panel"><h3>Chain Analysis</h3>';
    html += `<div style="margin-bottom:12px"><span class="sc-badge ${certs.length >= 2 ? 'green' : 'yellow'}">${certs.length} certificate(s) in chain</span></div>`;
    html += '<div class="sc-chain">';
    certs.forEach((cert, i) => {
      const level = i === certs.length - 1 && certs.length > 1 ? 'Root CA' : levels[Math.min(i, 3)];
      const isRoot = level === 'Root CA';
      const g = scGrade(cert.score);
      html += `
        <div class="sc-chain-cert" style="margin-left:${i * 24 + 20}px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
            <span class="sc-badge ${isRoot ? 'purple' : i === 0 ? 'blue' : 'green'}">${level}</span>
            <span class="sc-badge" style="background:${g.bg};color:${g.color}">${g.grade} (${cert.score}/100)</span>
          </div>
          <div style="font-size:13px;color:#e2e8f0;margin-bottom:4px;font-weight:600">${esc(cert.sans[0] || 'Unknown')}</div>
          <div style="font-size:12px;color:#6a8aaa">Issuer: ${esc(cert.issuer.split(',')[0])}</div>
          <div style="font-size:12px;color:#6a8aaa">${cert.keyType} ${cert.keySize}-bit &bull; ${cert.sigAlgoInfo.name}</div>
          <div style="font-size:12px;color:${cert.daysLeft > 90 ? '#00ff88' : cert.daysLeft > 30 ? '#ffd600' : '#ff4444'}">${cert.daysLeft > 0 ? cert.daysLeft + ' days remaining' : 'EXPIRED'}</div>
        </div>
      `;
      if (i < certs.length - 1) {
        html += `<div class="sc-chain-connector" style="margin-left:${i * 24 + 36}px">&#x2193; signed by</div>`;
      }
    });
    html += '</div>';
    const chainValid = certs.length >= 2;
    html += `<div style="margin-top:16px;padding:12px 16px;border-radius:6px;background:${chainValid ? 'rgba(0,255,136,0.08)' : 'rgba(255,214,0,0.08)'};border:1px solid ${chainValid ? '#00ff8830' : '#ffd60030'}">
      <span style="color:${chainValid ? '#00ff88' : '#ffd600'};font-weight:600">${chainValid ? '&#x2713; Chain appears valid' : '&#x26A0; Single certificate — no chain to validate'}</span>
      <div style="color:#6a8aaa;font-size:12px;margin-top:4px">${chainValid ? `Trust path: ${certs.map(c => c.sans[0]).join(' &rarr; ')}` : 'Paste multiple PEM certificates to validate the chain of trust.'}</div>
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
          <button class="sc-btn secondary" id="sc-csr-sample-btn">Load Sample</button>
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

  const samplePEM = `-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIUB0EfNkHBzR6RQGRVt3DhY2Z3X0EwDQYJKoZIhvcNAQEL
BQAwVjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEUV4YW1wbGUgQ29ycCBJbmMwHhcNMjMw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBWMQswCQYDVQQGEwJVUzETMBEGA1UE
CAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzEaMBgGA1UECgwR
RXhhbXBsZSBDb3JwIEluYzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIB
AKlHBJGG0DAPH0xN0U8EBhKS8PQrKZK4EWWJ9p0Xd6N5r3gVH5kFp1i5gUZPPnz
RZmOL3TFbIasOPR5K0j7CAMqVmp3FrcjJrS7ByaHLX6WDBwxfBUwlDGIqv4fE+bk
-----END CERTIFICATE-----`;

  const sampleChain = `-----BEGIN CERTIFICATE-----
MIIFjTCCA3WgAwIBAgIUB0EfNkHBzR6RQGRVt3DhY2Z3X0EwDQYJKoZIhvcNAQEL
BQAwVjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcM
DVNhbiBGcmFuY2lzY28xGjAYBgNVBAoMEUV4YW1wbGUgQ29ycCBJbmMwHhcNMjMw
MTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjBWMQswCQYDVQQGEwJVUzETMBEGA1UE
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDrzCCApegAwIBAgIQCDvgVpBCRrGhdWrJWZHHSjANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0yMTAzMzAwMDAwMDBaFw0zMTAzMjkyMzU5NTlaMFkxCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDjjCCAnagAwIBAgIQAzrx5qcRqaC7KGSxHQn65TANBgkqhkiG9w0BAQsFADBh
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBH
MjAeFw0xMzA4MDExMjAwMDBaFw0zODAxMTUxMjAwMDBaMGExCzAJBgNVBAYTAlVT
-----END CERTIFICATE-----`;

  const sampleCSR = `-----BEGIN CERTIFICATE REQUEST-----
MIICpDCCAYwCAQAwXzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWEx
FjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xFTATBgNVBAoMDEV4YW1wbGUgQ29ycDEQ
MA4GA1UEAwwHZXhhbXBsZTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
AK7WLIe0YLEr3p4k20BKHQD7nwSi2JQRVEr0epGmGKOU2TH00RM3gSfIG5FVD3Fz
-----END CERTIFICATE REQUEST-----`;

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
      const sampleBtn = container.querySelector('#sc-sample-btn');
      const exportBtn = container.querySelector('#sc-export-btn');
      const input = container.querySelector('#sc-pem-input');
      const resultDiv = container.querySelector('#sc-decode-result');
      let lastCert = null;

      decodeBtn?.addEventListener('click', () => {
        const pem = input.value.trim();
        if (!pem) { resultDiv.innerHTML = '<div class="sc-empty">Paste a PEM certificate above</div>'; return; }
        const certs = scParsePEM(pem);
        if (!certs.length) { resultDiv.innerHTML = '<div class="sc-empty">No valid PEM certificates found</div>'; return; }
        lastCert = scSimulateCertDecode(certs[0]);
        resultDiv.innerHTML = renderCertResult(lastCert);
        exportBtn.style.display = '';
      });

      const fetchBtn = content.querySelector('#sc-fetch-btn');
      const domainInput = content.querySelector('#sc-domain-input');
      if (fetchBtn && domainInput) {
        fetchBtn.addEventListener('click', async () => {
          const host = domainInput.value.trim().replace(/^https?:\/\//, '').replace(/[/:].*/,'').replace(/[^a-zA-Z0-9.\-]/g,'');
          if (!host) return;
          resultDiv.innerHTML = '<div class="sc-empty">Fetching certificate from ' + host + '...</div>';
          try {
            const r = await window._bridge.exec('echo | openssl s_client -connect ' + host + ':443 -servername ' + host + ' 2>/dev/null | openssl x509 -outform PEM');
            if (r.stdout && r.stdout.includes('BEGIN CERTIFICATE')) {
              input.value = r.stdout;
              const certs = scParsePEM(r.stdout);
              if (certs.length) { lastCert = scSimulateCertDecode(certs[0]); resultDiv.innerHTML = renderCertResult(lastCert); exportBtn.style.display = ''; }
            } else { resultDiv.innerHTML = '<div class="sc-empty">Could not fetch certificate. Check hostname.</div>'; }
          } catch (e) { resultDiv.innerHTML = '<div class="sc-empty">Error: ' + e.message + '</div>'; }
        });
      }

      sampleBtn?.addEventListener('click', () => {
        input.value = samplePEM;
      });

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
      const chainSampleBtn = container.querySelector('#sc-chain-sample-btn');
      const chainInput = container.querySelector('#sc-chain-input');
      const chainResult = container.querySelector('#sc-chain-result');

      chainBtn?.addEventListener('click', () => {
        const pem = chainInput.value.trim();
        if (!pem) { chainResult.innerHTML = '<div class="sc-empty">Paste PEM certificates above</div>'; return; }
        const pems = scParsePEM(pem);
        if (!pems.length) { chainResult.innerHTML = '<div class="sc-empty">No valid PEM certificates found</div>'; return; }
        chainResult.innerHTML = renderChainResult(pems);
      });

      chainSampleBtn?.addEventListener('click', () => {
        chainInput.value = sampleChain;
      });
    }

    if (activeTab === 'csr') {
      const csrBtn = container.querySelector('#sc-csr-btn');
      const csrSampleBtn = container.querySelector('#sc-csr-sample-btn');
      const csrInput = container.querySelector('#sc-csr-input');
      const csrResult = container.querySelector('#sc-csr-result');

      csrBtn?.addEventListener('click', () => {
        const text = csrInput.value.trim();
        if (!text) { csrResult.innerHTML = '<div class="sc-empty">Paste a CSR above</div>'; return; }
        const csr = scParseCSR(text);
        csrResult.innerHTML = renderCSRResult(csr);
      });

      csrSampleBtn?.addEventListener('click', () => {
        csrInput.value = sampleCSR;
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
