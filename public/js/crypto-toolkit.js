// Cryptography Toolkit — comprehensive client-side crypto analysis tool
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

// ============================================================================
// CRYPTO ATTACK REFERENCE — 35+ attacks
// ============================================================================
const CRYPTO_ATTACKS = [
  { name: 'Padding Oracle', year: 2002, target: 'CBC mode block ciphers', severity: 'Critical', desc: 'Attacker decrypts ciphertext by observing padding error responses. Each byte can be recovered in 256 attempts max. Affects any system that reveals whether decryption padding is valid.', mitigation: 'Use authenticated encryption (AES-GCM). Never reveal padding errors to the client. Use constant-time comparison.', cve: 'CVE-2014-3566 (POODLE)' },
  { name: 'BEAST', year: 2011, target: 'TLS 1.0 CBC mode', severity: 'High', desc: 'Browser Exploit Against SSL/TLS. Exploits predictable IV in TLS 1.0 CBC mode via chosen-plaintext attack to decrypt HTTPS cookies.', mitigation: 'Use TLS 1.2+. Prefer AES-GCM. Apply 1/n-1 record splitting workaround.', cve: 'CVE-2011-3389' },
  { name: 'POODLE', year: 2014, target: 'SSL 3.0', severity: 'High', desc: 'Padding Oracle On Downgraded Legacy Encryption. Exploits SSL 3.0 padding to recover plaintext bytes. Forces protocol downgrade then exploits.', mitigation: 'Disable SSL 3.0 entirely. Use TLS_FALLBACK_SCSV to prevent downgrade attacks.', cve: 'CVE-2014-3566' },
  { name: 'DROWN', year: 2016, target: 'SSLv2 cross-protocol', severity: 'Critical', desc: 'Decrypting RSA with Obsolete and Weakened eNcryption. Even if SSLv2 is only enabled on one server sharing the RSA key, all servers using that key are vulnerable.', mitigation: 'Disable SSLv2 on ALL servers. Use unique RSA keys per server.', cve: 'CVE-2016-0800' },
  { name: 'Bleichenbacher', year: 1998, target: 'PKCS#1 v1.5 RSA', severity: 'Critical', desc: 'Adaptive chosen-ciphertext attack on RSA PKCS#1 v1.5 padding. Can decrypt RSA ciphertext or forge signatures by observing error messages.', mitigation: 'Use RSA-OAEP instead of PKCS#1 v1.5. Implement constant-time padding checks.', cve: 'CVE-2017-6168 (ROBOT)' },
  { name: 'ROBOT', year: 2017, target: 'RSA encryption in TLS', severity: 'Critical', desc: 'Return Of Bleichenbacher Oracle Threat. Found that many TLS implementations still leak padding information, enabling Bleichenbacher attack 19 years later.', mitigation: 'Disable RSA key exchange in TLS. Use ECDHE key exchange.', cve: 'CVE-2017-6168' },
  { name: 'Sweet32', year: 2016, target: '64-bit block ciphers', severity: 'Medium', desc: 'Birthday attack on 64-bit block ciphers (3DES, Blowfish). After 2^32 blocks (~32 GB), collisions reveal plaintext XOR.', mitigation: 'Disable 3DES and other 64-bit block ciphers. Use AES (128-bit blocks).', cve: 'CVE-2016-2183' },
  { name: 'Lucky13', year: 2013, target: 'TLS CBC mode', severity: 'Medium', desc: 'Timing side-channel in CBC MAC-then-encrypt. Padding length affects processing time, enabling byte-by-byte plaintext recovery.', mitigation: 'Use AES-GCM (encrypt-then-MAC). Apply constant-time processing for all padding lengths.', cve: 'CVE-2013-0169' },
  { name: 'Raccoon', year: 2020, target: 'TLS-DH(E) key exchange', severity: 'Medium', desc: 'Timing attack on DH key exchange. Server processing time reveals information about the premaster secret when it has leading zero bytes.', mitigation: 'Upgrade to TLS 1.3 (not affected). Use constant-time DH implementations.', cve: 'CVE-2020-1968' },
  { name: 'CRIME', year: 2012, target: 'TLS compression', severity: 'High', desc: 'Compression Ratio Info-leak Made Easy. Exploits TLS compression to recover secret cookies by measuring compressed response sizes.', mitigation: 'Disable TLS-level compression. Use HTTP-level compression only for non-secret content.', cve: 'CVE-2012-4929' },
  { name: 'BREACH', year: 2013, target: 'HTTP compression', severity: 'Medium', desc: 'Extension of CRIME to HTTP compression. Recovers secrets in HTTP response bodies by measuring compressed sizes across requests.', mitigation: 'Separate secrets from user-input in responses. Use CSRF tokens per request. Add random padding.', cve: 'CVE-2013-3587' },
  { name: 'Heartbleed', year: 2014, target: 'OpenSSL TLS heartbeat', severity: 'Critical', desc: 'Buffer over-read in OpenSSL heartbeat extension. Leaks up to 64KB of server memory per request, including private keys and session data.', mitigation: 'Update OpenSSL to 1.0.1g+. Revoke and reissue all certificates. Reset all passwords.', cve: 'CVE-2014-0160' },
  { name: 'FREAK', year: 2015, target: 'Export-grade RSA', severity: 'High', desc: 'Factoring RSA Export Keys. MITM can force export-grade (512-bit) RSA ciphers, which are easily factorable.', mitigation: 'Remove all export cipher suites. Disable RSA_EXPORT key exchange.', cve: 'CVE-2015-0204' },
  { name: 'Logjam', year: 2015, target: 'Export-grade DHE', severity: 'High', desc: 'MITM forces export-grade 512-bit DH parameters, which can be precomputed. 1024-bit DH groups may also be vulnerable to nation-states.', mitigation: 'Use 2048-bit+ DH groups. Disable DHE_EXPORT. Prefer ECDHE.', cve: 'CVE-2015-4000' },
  { name: 'ROCA', year: 2017, target: 'Infineon RSA key generation', severity: 'High', desc: 'Return of Coppersmith Attack. Infineon TPMs generated RSA keys with detectable structure, enabling factorization of 2048-bit keys.', mitigation: 'Regenerate all keys from affected Infineon TPMs. Test keys with the ROCA detection tool.', cve: 'CVE-2017-15361' },
  { name: 'Terrapin', year: 2023, target: 'SSH protocol', severity: 'Medium', desc: 'SSH prefix truncation attack. MITM can remove messages from the beginning of the encrypted channel, downgrading security extensions.', mitigation: 'Update SSH client and server. Disable chacha20-poly1305@openssh.com and CBC-EtM ciphers if not patched.', cve: 'CVE-2023-48795' },
  { name: 'Hash Length Extension', year: 2009, target: 'MD5, SHA-1, SHA-256', severity: 'Medium', desc: 'Given H(secret||message) and length of secret, attacker can compute H(secret||message||padding||extension) without knowing the secret.', mitigation: 'Use HMAC instead of H(secret||message). Or use SHA-3 (not vulnerable).', cve: 'N/A' },
  { name: 'Birthday Attack', year: 1979, target: 'Any hash function', severity: 'Varies', desc: 'Finding two inputs with the same hash. For n-bit hash, expected ~2^(n/2) attempts. 64-bit hash = 2^32 attempts (trivial). MD5 (128-bit) = 2^64.', mitigation: 'Use hashes with 256+ bits of output (SHA-256, SHA-3-256). Avoid MD5, SHA-1 for collision resistance.', cve: 'N/A' },
  { name: 'Chosen Plaintext', year: 1930, target: 'Weak encryption', severity: 'Varies', desc: 'Attacker can encrypt arbitrary plaintexts and analyze the ciphertexts. Breaks ECB mode, weak stream ciphers, and deterministic encryption.', mitigation: 'Use IND-CPA secure schemes (CBC, CTR, GCM with random IV/nonce). Never use ECB mode.', cve: 'N/A' },
  { name: 'IV Reuse / Nonce Reuse', year: 'N/A', target: 'CTR, GCM, ChaCha20', severity: 'Critical', desc: 'Reusing a nonce with the same key in stream ciphers or AEAD modes reveals XOR of plaintexts (CTR) or breaks authentication (GCM).', mitigation: 'Use random 96-bit nonces for GCM. Use XChaCha20 (192-bit nonce) for nonce-misuse resistance. Use SIV mode.', cve: 'N/A' },
  { name: 'AES-ECB Penguin', year: 2004, target: 'AES-ECB mode', severity: 'High', desc: 'ECB encrypts identical blocks to identical ciphertext. Patterns in plaintext are visible in ciphertext (the famous "ECB penguin" image).', mitigation: 'Never use ECB mode. Use CBC, CTR, or GCM with random IV/nonce.', cve: 'N/A' },
  { name: 'Brute Force', year: 'N/A', target: 'Short keys', severity: 'Varies', desc: 'Exhaustive key search. DES (56-bit) broken in 22 hours by Deep Crack (1998). 2DES provides only 57-bit effective security due to meet-in-the-middle.', mitigation: 'Use AES-128 minimum (128-bit key = 2^128 attempts). Use AES-256 for post-quantum resistance.', cve: 'N/A' },
  { name: 'Downgrade Attack', year: 'N/A', target: 'TLS negotiation', severity: 'High', desc: 'MITM forces client and server to negotiate a weaker cipher suite or protocol version than both support.', mitigation: 'Implement TLS_FALLBACK_SCSV. Disable all weak protocols (SSL 2/3, TLS 1.0/1.1) and weak ciphers.', cve: 'N/A' },
  { name: 'Side-Channel (Timing)', year: 1996, target: 'Any crypto implementation', severity: 'Varies', desc: 'Measuring execution time to extract secret keys. Affects RSA, AES, HMAC comparison, and more. Even remote timing over a network can work.', mitigation: 'Use constant-time implementations. Use blinding for RSA. Use constant-time comparison for MACs/hashes.', cve: 'N/A' },
  { name: 'Quantum Threat (Shor)', year: 1994, target: 'RSA, ECDSA, DH, ECDH', severity: 'Future', desc: 'Shor algorithm on a quantum computer can factor integers and compute discrete logs in polynomial time, breaking all current public-key crypto.', mitigation: 'Transition to post-quantum algorithms: ML-KEM (Kyber), ML-DSA (Dilithium), SLH-DSA (SPHINCS+). Use hybrid key exchange.', cve: 'N/A' },
  { name: 'Quantum Threat (Grover)', year: 1996, target: 'Symmetric ciphers, hashes', severity: 'Future', desc: 'Grover algorithm provides quadratic speedup for brute force. AES-128 becomes effectively 64-bit. AES-256 remains safe (128-bit effective).', mitigation: 'Use AES-256 for long-term post-quantum security. Use SHA-384/512 for hash-based post-quantum security.', cve: 'N/A' },
];

// ============================================================================
// CIPHER SUITE GRADING
// ============================================================================
const CIPHER_GRADES = {
  'TLS_AES_256_GCM_SHA384': { grade: 'A+', note: 'TLS 1.3 with AES-256-GCM. Best available.' },
  'TLS_AES_128_GCM_SHA256': { grade: 'A+', note: 'TLS 1.3 with AES-128-GCM. Excellent.' },
  'TLS_CHACHA20_POLY1305_SHA256': { grade: 'A+', note: 'TLS 1.3 with ChaCha20. Excellent, especially for mobile.' },
  'ECDHE-RSA-AES256-GCM-SHA384': { grade: 'A', note: 'TLS 1.2 ECDHE + AES-256-GCM. Strong.' },
  'ECDHE-RSA-AES128-GCM-SHA256': { grade: 'A', note: 'TLS 1.2 ECDHE + AES-128-GCM. Strong.' },
  'ECDHE-RSA-CHACHA20-POLY1305': { grade: 'A', note: 'TLS 1.2 ECDHE + ChaCha20. Strong.' },
  'DHE-RSA-AES256-GCM-SHA384': { grade: 'B+', note: 'DH key exchange. Use ECDHE instead for performance.' },
  'DHE-RSA-AES128-GCM-SHA256': { grade: 'B+', note: 'DH key exchange. Acceptable but ECDHE preferred.' },
  'ECDHE-RSA-AES256-SHA384': { grade: 'B', note: 'CBC mode. Prefer GCM. Vulnerable to Lucky13.' },
  'ECDHE-RSA-AES128-SHA256': { grade: 'B', note: 'CBC mode. Prefer GCM.' },
  'AES256-GCM-SHA384': { grade: 'C', note: 'No forward secrecy (no ECDHE/DHE). RSA key exchange.' },
  'AES128-GCM-SHA256': { grade: 'C', note: 'No forward secrecy. RSA key exchange.' },
  'AES256-SHA256': { grade: 'C', note: 'No forward secrecy, CBC mode.' },
  'AES128-SHA': { grade: 'D', note: 'No forward secrecy, CBC mode, SHA-1 MAC.' },
  'DES-CBC3-SHA': { grade: 'D', note: '3DES is 64-bit block cipher. Vulnerable to Sweet32.' },
  'RC4-SHA': { grade: 'F', note: 'RC4 is broken. Multiple known biases enable plaintext recovery.' },
  'RC4-MD5': { grade: 'F', note: 'RC4 + MD5. Both broken. Never use.' },
  'DES-CBC-SHA': { grade: 'F', note: 'DES is 56-bit key. Brute-forceable in hours.' },
  'NULL-SHA': { grade: 'F', note: 'No encryption at all. Authentication only.' },
  'NULL-MD5': { grade: 'F', note: 'No encryption, weak authentication. Completely broken.' },
  'EXP-RC4-MD5': { grade: 'F', note: 'Export cipher. 40-bit key. Trivially broken.' },
  'EXP-DES-CBC-SHA': { grade: 'F', note: 'Export cipher. 40-bit key. Trivially broken.' },
};

// ============================================================================
// KEY SIZE RECOMMENDATIONS
// ============================================================================
const KEY_RECOMMENDATIONS = [
  { algorithm: 'AES', securityLevel: '128-bit', recommended: '128-bit key', postQuantum: '256-bit key (Grover halves effective strength)', note: 'AES-128 is secure today. AES-256 for 20+ year security.' },
  { algorithm: 'RSA', securityLevel: '112-bit', recommended: '2048-bit key', postQuantum: 'Migrate to ML-KEM (Kyber)', note: '2048-bit RSA ~ 112-bit security. Use 3072+ for 128-bit. 4096 for longevity.' },
  { algorithm: 'ECDSA/ECDH', securityLevel: '128-bit', recommended: 'P-256 (secp256r1)', postQuantum: 'Migrate to ML-DSA (Dilithium)', note: 'P-256 = 128-bit security. P-384 for 192-bit. Ed25519 for signing.' },
  { algorithm: 'SHA-2', securityLevel: '128-bit collision', recommended: 'SHA-256', postQuantum: 'SHA-384 or SHA-512', note: 'SHA-256 = 128-bit collision resistance. SHA-512 for post-quantum margin.' },
  { algorithm: 'HMAC', securityLevel: 'Same as hash', recommended: 'HMAC-SHA256', postQuantum: 'HMAC-SHA512', note: 'Key should be >= hash output length.' },
  { algorithm: 'Diffie-Hellman', securityLevel: '112-bit', recommended: '2048-bit group', postQuantum: 'Migrate to ML-KEM', note: 'Use well-known groups (RFC 7919). Never generate custom DH parameters.' },
  { algorithm: 'ChaCha20-Poly1305', securityLevel: '256-bit', recommended: '256-bit key', postQuantum: 'Secure (256-bit effective with Grover)', note: 'Excellent alternative to AES-GCM, especially on platforms without AES-NI.' },
  { algorithm: 'Argon2id', securityLevel: 'Configurable', recommended: 'm=65536, t=3, p=4', postQuantum: 'Increase memory parameter', note: 'Best password hashing. Memory-hard and GPU-resistant.' },
  { algorithm: 'bcrypt', securityLevel: 'Configurable', recommended: 'cost=12', postQuantum: 'Migrate to Argon2id long-term', note: 'Good password hashing. Max 72-byte input length.' },
];

// ============================================================================
// HELPER: hex encode/decode
// ============================================================================
function hex(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''); }
function fromHex(h) { var bytes = []; for (var i = 0; i < h.length; i += 2) bytes.push(parseInt(h.substr(i, 2), 16)); return new Uint8Array(bytes); }
function b64(buf) { return btoa(String.fromCharCode.apply(null, new Uint8Array(buf))); }
function entropy(data) {
  var freq = {};
  for (var i = 0; i < data.length; i++) {
    var b = data[i];
    freq[b] = (freq[b] || 0) + 1;
  }
  var ent = 0;
  var len = data.length;
  Object.values(freq).forEach(function(count) {
    var p = count / len;
    if (p > 0) ent -= p * Math.log2(p);
  });
  return ent;
}

// ============================================================================
// RENDER
// ============================================================================
export function renderCryptoToolkit(main) {
  var activeTab = 'encrypt';

  function render() {
    main.innerHTML =
      '<h1 class="pg-h1">Cryptography Toolkit</h1>' +
      '<p class="muted pg-sub">Client-side cryptographic operations, analysis, and reference. Nothing leaves your browser.</p>' +
      '<div class="tab-bar" style="overflow-x:auto;flex-wrap:nowrap">' +
        '<button class="tab' + (activeTab === 'encrypt' ? ' active' : '') + '" data-tab="encrypt">AES Encrypt/Decrypt</button>' +
        '<button class="tab' + (activeTab === 'rsa' ? ' active' : '') + '" data-tab="rsa">RSA Operations</button>' +
        '<button class="tab' + (activeTab === 'hash' ? ' active' : '') + '" data-tab="hash">Hashing</button>' +
        '<button class="tab' + (activeTab === 'entropy' ? ' active' : '') + '" data-tab="entropy">Entropy Analyzer</button>' +
        '<button class="tab' + (activeTab === 'random' ? ' active' : '') + '" data-tab="random">Random Generator</button>' +
        '<button class="tab' + (activeTab === 'ciphers' ? ' active' : '') + '" data-tab="ciphers">Cipher Suite Grader</button>' +
        '<button class="tab' + (activeTab === 'keys' ? ' active' : '') + '" data-tab="keys">Key Recommendations</button>' +
        '<button class="tab' + (activeTab === 'attacks' ? ' active' : '') + '" data-tab="attacks">Crypto Attacks</button>' +
        '<button class="tab' + (activeTab === 'dh' ? ' active' : '') + '" data-tab="dh">Diffie-Hellman Demo</button>' +
      '</div>' +
      '<div id="ct-content" style="margin-top:12px"></div>';

    main.querySelector('.tab-bar').onclick = function(e) {
      var b = e.target.closest('.tab');
      if (!b) return;
      activeTab = b.dataset.tab;
      render();
    };

    var content = main.querySelector('#ct-content');
    if (activeTab === 'encrypt') renderEncryptTab(content);
    else if (activeTab === 'rsa') renderRSATab(content);
    else if (activeTab === 'hash') renderHashTab(content);
    else if (activeTab === 'entropy') renderEntropyTab(content);
    else if (activeTab === 'random') renderRandomTab(content);
    else if (activeTab === 'ciphers') renderCiphersTab(content);
    else if (activeTab === 'keys') renderKeysTab(content);
    else if (activeTab === 'attacks') renderAttacksTab(content);
    else if (activeTab === 'dh') renderDHTab(content);
  }

  function renderEncryptTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">AES Encryption / Decryption</h2>' +
      '<p class="muted" style="margin-bottom:12px">All operations use the Web Crypto API (SubtleCrypto). Nothing is sent anywhere.</p>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
        '<div>' +
          '<label style="font-size:.78rem;color:var(--mut)">Plaintext / Ciphertext</label>' +
          '<textarea class="tk-in" id="ct-aes-input" rows="6" placeholder="Enter text to encrypt or hex ciphertext to decrypt..."></textarea>' +
        '</div>' +
        '<div>' +
          '<label style="font-size:.78rem;color:var(--mut)">Result</label>' +
          '<textarea class="tk-in" id="ct-aes-output" rows="6" readonly style="color:var(--acc)"></textarea>' +
        '</div>' +
      '</div>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;margin:12px 0;align-items:center">' +
        '<label style="font-size:.78rem;color:var(--mut)">Key (hex):</label>' +
        '<input type="text" class="tk-f" id="ct-aes-key" placeholder="256-bit hex key (64 chars) or leave empty to generate" style="max-width:500px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Mode:</label>' +
        '<select class="tk-f" id="ct-aes-mode" style="max-width:120px">' +
          '<option value="GCM">AES-GCM</option>' +
          '<option value="CBC">AES-CBC</option>' +
          '<option value="CTR">AES-CTR</option>' +
        '</select>' +
        '<label style="font-size:.78rem;color:var(--mut)">Key size:</label>' +
        '<select class="tk-f" id="ct-aes-size" style="max-width:100px">' +
          '<option value="256">256-bit</option>' +
          '<option value="128">128-bit</option>' +
          '<option value="192">192-bit</option>' +
        '</select>' +
      '</div>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="ct-aes-enc">Encrypt</button>' +
        '<button class="btn sm ghost" id="ct-aes-dec">Decrypt</button>' +
        '<button class="btn sm ghost" id="ct-aes-genkey">Generate Key</button>' +
      '</div>';

    container.querySelector('#ct-aes-genkey').onclick = async function() {
      var size = parseInt(container.querySelector('#ct-aes-size').value);
      var key = new Uint8Array(size / 8);
      crypto.getRandomValues(key);
      container.querySelector('#ct-aes-key').value = hex(key);
    };

    container.querySelector('#ct-aes-enc').onclick = async function() {
      try {
        var input = container.querySelector('#ct-aes-input').value;
        var keyHex = container.querySelector('#ct-aes-key').value;
        var mode = container.querySelector('#ct-aes-mode').value;
        var size = parseInt(container.querySelector('#ct-aes-size').value);
        if (!keyHex) { var kb = new Uint8Array(size / 8); crypto.getRandomValues(kb); keyHex = hex(kb); container.querySelector('#ct-aes-key').value = keyHex; }
        var keyBytes = fromHex(keyHex);
        var iv = crypto.getRandomValues(new Uint8Array(mode === 'GCM' ? 12 : 16));
        var algo = mode === 'GCM' ? { name: 'AES-GCM', iv: iv } : mode === 'CBC' ? { name: 'AES-CBC', iv: iv } : { name: 'AES-CTR', counter: iv, length: 64 };
        var cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-' + mode }, false, ['encrypt']);
        var enc = await crypto.subtle.encrypt(algo, cryptoKey, new TextEncoder().encode(input));
        container.querySelector('#ct-aes-output').value = 'IV: ' + hex(iv) + '\nCiphertext: ' + hex(enc) + '\nBase64: ' + b64(enc);
      } catch (e) { container.querySelector('#ct-aes-output').value = 'Error: ' + e.message; }
    };

    container.querySelector('#ct-aes-dec').onclick = async function() {
      try {
        var input = container.querySelector('#ct-aes-input').value;
        var keyHex = container.querySelector('#ct-aes-key').value;
        var mode = container.querySelector('#ct-aes-mode').value;
        var lines = input.split('\n');
        var ivHex = '', ctHex = '';
        lines.forEach(function(l) { if (l.startsWith('IV:')) ivHex = l.split(':')[1].trim(); if (l.startsWith('Ciphertext:')) ctHex = l.split(':')[1].trim(); });
        if (!ivHex || !ctHex) { container.querySelector('#ct-aes-output').value = 'Paste the encrypted output (IV + Ciphertext lines)'; return; }
        var keyBytes = fromHex(keyHex);
        var iv = fromHex(ivHex);
        var ct = fromHex(ctHex);
        var algo = mode === 'GCM' ? { name: 'AES-GCM', iv: iv } : mode === 'CBC' ? { name: 'AES-CBC', iv: iv } : { name: 'AES-CTR', counter: iv, length: 64 };
        var cryptoKey = await crypto.subtle.importKey('raw', keyBytes, { name: 'AES-' + mode }, false, ['decrypt']);
        var dec = await crypto.subtle.decrypt(algo, cryptoKey, ct);
        container.querySelector('#ct-aes-output').value = new TextDecoder().decode(dec);
      } catch (e) { container.querySelector('#ct-aes-output').value = 'Decryption failed: ' + e.message; }
    };
  }

  function renderRSATab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">RSA Key Operations</h2>' +
      '<p class="muted" style="margin-bottom:12px">Generate RSA key pairs, encrypt/decrypt, and sign/verify using SubtleCrypto.</p>' +
      '<div class="tk-btns" style="margin-bottom:12px">' +
        '<button class="btn sm" id="ct-rsa-gen2048">Generate 2048-bit</button>' +
        '<button class="btn sm ghost" id="ct-rsa-gen4096">Generate 4096-bit</button>' +
      '</div>' +
      '<div style="display:grid;grid-template-columns:1fr 1fr;gap:12px">' +
        '<div><label style="font-size:.78rem;color:var(--mut)">Public Key (SPKI, Base64)</label><textarea class="tk-in" id="ct-rsa-pub" rows="4" readonly></textarea></div>' +
        '<div><label style="font-size:.78rem;color:var(--mut)">Private Key (PKCS8, Base64)</label><textarea class="tk-in" id="ct-rsa-priv" rows="4" readonly></textarea></div>' +
      '</div>' +
      '<div style="margin-top:12px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Input text</label>' +
        '<textarea class="tk-in" id="ct-rsa-input" rows="3" placeholder="Text to encrypt or sign..."></textarea>' +
      '</div>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="ct-rsa-enc">Encrypt (RSA-OAEP)</button>' +
        '<button class="btn sm ghost" id="ct-rsa-sign">Sign (RSA-PSS)</button>' +
      '</div>' +
      '<pre class="tk-out" id="ct-rsa-out" style="margin-top:8px;min-height:40px"></pre>';

    var rsaKeyPair = null;
    async function genRSA(bits) {
      rsaKeyPair = await crypto.subtle.generateKey({ name: 'RSA-OAEP', modulusLength: bits, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['encrypt', 'decrypt']);
      var pub = await crypto.subtle.exportKey('spki', rsaKeyPair.publicKey);
      var priv = await crypto.subtle.exportKey('pkcs8', rsaKeyPair.privateKey);
      container.querySelector('#ct-rsa-pub').value = b64(pub);
      container.querySelector('#ct-rsa-priv').value = b64(priv);
      container.querySelector('#ct-rsa-out').textContent = bits + '-bit RSA key pair generated.';
    }
    container.querySelector('#ct-rsa-gen2048').onclick = function() { genRSA(2048); };
    container.querySelector('#ct-rsa-gen4096').onclick = function() { genRSA(4096); };
    container.querySelector('#ct-rsa-enc').onclick = async function() {
      if (!rsaKeyPair) { container.querySelector('#ct-rsa-out').textContent = 'Generate a key pair first.'; return; }
      try {
        var text = container.querySelector('#ct-rsa-input').value;
        var enc = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, rsaKeyPair.publicKey, new TextEncoder().encode(text));
        var dec = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, rsaKeyPair.privateKey, enc);
        container.querySelector('#ct-rsa-out').textContent = 'Ciphertext (hex): ' + hex(enc) + '\n\nDecrypted: ' + new TextDecoder().decode(dec);
      } catch (e) { container.querySelector('#ct-rsa-out').textContent = 'Error: ' + e.message; }
    };
    container.querySelector('#ct-rsa-sign').onclick = async function() {
      if (!rsaKeyPair) { container.querySelector('#ct-rsa-out').textContent = 'Generate a key pair first.'; return; }
      try {
        var signKey = await crypto.subtle.generateKey({ name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-256' }, true, ['sign', 'verify']);
        var text = container.querySelector('#ct-rsa-input').value;
        var sig = await crypto.subtle.sign({ name: 'RSA-PSS', saltLength: 32 }, signKey.privateKey, new TextEncoder().encode(text));
        var valid = await crypto.subtle.verify({ name: 'RSA-PSS', saltLength: 32 }, signKey.publicKey, sig, new TextEncoder().encode(text));
        container.querySelector('#ct-rsa-out').textContent = 'Signature (hex): ' + hex(sig) + '\n\nVerification: ' + (valid ? 'VALID' : 'INVALID');
      } catch (e) { container.querySelector('#ct-rsa-out').textContent = 'Error: ' + e.message; }
    };
  }

  function renderHashTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Hash Generator</h2>' +
      '<p class="muted" style="margin-bottom:12px">Compute cryptographic hashes using SubtleCrypto. Paste text or drop a file.</p>' +
      '<textarea class="tk-in" id="ct-hash-input" rows="4" placeholder="Enter text to hash..."></textarea>' +
      '<div class="tk-btns">' +
        '<button class="btn sm" id="ct-hash-all">Hash All</button>' +
        '<button class="btn sm ghost" id="ct-hash-compare">Compare Two Hashes</button>' +
      '</div>' +
      '<pre class="tk-out" id="ct-hash-out" style="margin-top:8px"></pre>' +
      '<div style="margin-top:16px">' +
        '<h3 style="font-size:.85rem;margin-bottom:6px">HMAC Generator</h3>' +
        '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:8px">' +
          '<input type="text" class="tk-f" id="ct-hmac-key" placeholder="HMAC key" style="max-width:300px">' +
          '<button class="btn sm" id="ct-hmac-gen">Generate HMAC-SHA256</button>' +
        '</div>' +
        '<pre class="tk-out" id="ct-hmac-out"></pre>' +
      '</div>';

    container.querySelector('#ct-hash-all').onclick = async function() {
      var text = container.querySelector('#ct-hash-input').value;
      var data = new TextEncoder().encode(text);
      var algos = ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512'];
      var results = [];
      for (var i = 0; i < algos.length; i++) {
        var h = await crypto.subtle.digest(algos[i], data);
        results.push(algos[i] + ': ' + hex(h));
      }
      container.querySelector('#ct-hash-out').textContent = results.join('\n');
    };

    container.querySelector('#ct-hash-compare').onclick = function() {
      var out = container.querySelector('#ct-hash-out');
      out.innerHTML = '';
      var wrap = document.createElement('div');
      wrap.innerHTML = '<input type="text" class="tk-f" id="ct-h1" placeholder="Hash 1" style="margin-bottom:4px;display:block;width:100%"><input type="text" class="tk-f" id="ct-h2" placeholder="Hash 2" style="margin-bottom:4px;display:block;width:100%"><button class="btn sm" id="ct-hcmp">Compare</button><div id="ct-hresult" style="margin-top:8px"></div>';
      out.appendChild(wrap);
      wrap.querySelector('#ct-hcmp').onclick = function() {
        var h1 = wrap.querySelector('#ct-h1').value.trim().toLowerCase();
        var h2 = wrap.querySelector('#ct-h2').value.trim().toLowerCase();
        var match = h1 === h2 && h1.length > 0;
        wrap.querySelector('#ct-hresult').innerHTML = match ? '<span style="color:#00e676;font-weight:600">MATCH</span> — Hashes are identical.' : '<span style="color:#ff1744;font-weight:600">NO MATCH</span> — Hashes differ.';
      };
    };

    container.querySelector('#ct-hmac-gen').onclick = async function() {
      try {
        var text = container.querySelector('#ct-hash-input').value;
        var keyText = container.querySelector('#ct-hmac-key').value;
        var keyData = new TextEncoder().encode(keyText);
        var cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
        var sig = await crypto.subtle.sign('HMAC', cryptoKey, new TextEncoder().encode(text));
        container.querySelector('#ct-hmac-out').textContent = 'HMAC-SHA256: ' + hex(sig);
      } catch (e) { container.querySelector('#ct-hmac-out').textContent = 'Error: ' + e.message; }
    };
  }

  function renderEntropyTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Entropy Analyzer</h2>' +
      '<p class="muted" style="margin-bottom:12px">Calculate Shannon entropy and byte distribution of any data. High entropy (>7.5) suggests encryption or compression.</p>' +
      '<textarea class="tk-in" id="ct-ent-input" rows="6" placeholder="Paste text, hex, or base64 data..."></textarea>' +
      '<div class="tk-btns"><button class="btn sm" id="ct-ent-calc">Analyze Entropy</button></div>' +
      '<div id="ct-ent-result" style="margin-top:12px"></div>' +
      '<canvas id="ct-ent-chart" width="600" height="200" style="margin-top:12px;background:var(--card);border:1px solid var(--line);border-radius:6px;width:100%;max-width:600px"></canvas>';

    container.querySelector('#ct-ent-calc').onclick = function() {
      var input = container.querySelector('#ct-ent-input').value;
      var data = new TextEncoder().encode(input);
      var ent = entropy(data);
      var maxEnt = 8;
      var pct = (ent / maxEnt * 100).toFixed(1);
      var assessment = ent > 7.5 ? 'Very high — likely encrypted or compressed' : ent > 6 ? 'High — possibly compressed or binary' : ent > 4 ? 'Moderate — structured data' : ent > 2 ? 'Low — natural language text' : 'Very low — repetitive data';
      var color = ent > 7.5 ? '#ff1744' : ent > 6 ? '#ff9100' : ent > 4 ? '#ffd600' : '#00e676';

      container.querySelector('#ct-ent-result').innerHTML =
        '<div style="display:flex;gap:16px;flex-wrap:wrap">' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
            '<div style="font-size:1.6rem;font-weight:700;color:' + color + '">' + ent.toFixed(4) + '</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">BITS/BYTE (max 8.0)</div></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px">' +
            '<div style="font-size:1.2rem;font-weight:700">' + data.length + '</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">BYTES</div></div>' +
          '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px 20px;flex:1;min-width:200px">' +
            '<div style="font-size:.85rem;font-weight:600;color:' + color + '">' + esc(assessment) + '</div>' +
            '<div style="font-size:.72rem;color:var(--mut)">' + pct + '% of maximum entropy</div></div>' +
        '</div>';

      // Draw histogram
      var canvas = container.querySelector('#ct-ent-chart');
      var ctx = canvas.getContext('2d');
      canvas.width = canvas.offsetWidth;
      canvas.height = 200;
      ctx.clearRect(0, 0, canvas.width, canvas.height);
      var freq = new Array(256).fill(0);
      for (var i = 0; i < data.length; i++) freq[data[i]]++;
      var maxFreq = Math.max.apply(null, freq) || 1;
      var barW = canvas.width / 256;
      for (var b = 0; b < 256; b++) {
        var h = (freq[b] / maxFreq) * (canvas.height - 20);
        var hue = (b / 256) * 200 + 180;
        ctx.fillStyle = 'hsl(' + hue + ', 70%, 50%)';
        ctx.fillRect(b * barW, canvas.height - 10 - h, Math.max(barW - 0.5, 1), h);
      }
      ctx.fillStyle = '#888';
      ctx.font = '10px system-ui';
      ctx.fillText('0x00', 2, canvas.height - 1);
      ctx.fillText('0xFF', canvas.width - 25, canvas.height - 1);
      ctx.fillText('Byte value distribution', canvas.width / 2 - 60, 12);
    };
  }

  function renderRandomTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Cryptographic Random Generator</h2>' +
      '<p class="muted" style="margin-bottom:12px">Generate cryptographically secure random data using crypto.getRandomValues().</p>' +
      '<div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:12px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Bytes:</label>' +
        '<input type="number" class="tk-f" id="ct-rng-bytes" value="32" min="1" max="1024" style="max-width:100px">' +
        '<label style="font-size:.78rem;color:var(--mut)">Format:</label>' +
        '<select class="tk-f" id="ct-rng-fmt" style="max-width:120px">' +
          '<option value="hex">Hex</option><option value="base64">Base64</option><option value="decimal">Decimal</option><option value="binary">Binary</option>' +
        '</select>' +
        '<button class="btn sm" id="ct-rng-gen">Generate</button>' +
      '</div>' +
      '<pre class="tk-out" id="ct-rng-out" style="word-break:break-all"></pre>';

    container.querySelector('#ct-rng-gen').onclick = function() {
      var n = parseInt(container.querySelector('#ct-rng-bytes').value) || 32;
      n = Math.min(Math.max(n, 1), 1024);
      var buf = new Uint8Array(n);
      crypto.getRandomValues(buf);
      var fmt = container.querySelector('#ct-rng-fmt').value;
      var out;
      if (fmt === 'hex') out = hex(buf);
      else if (fmt === 'base64') out = b64(buf);
      else if (fmt === 'decimal') out = Array.from(buf).join(' ');
      else out = Array.from(buf).map(function(b) { return b.toString(2).padStart(8, '0'); }).join(' ');
      container.querySelector('#ct-rng-out').textContent = out;
    };
  }

  function renderCiphersTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">TLS Cipher Suite Grader</h2>' +
      '<p class="muted" style="margin-bottom:12px">Paste a list of cipher suites (one per line) to grade each one.</p>' +
      '<textarea class="tk-in" id="ct-cs-input" rows="6" placeholder="Paste cipher suites, e.g.:\nTLS_AES_256_GCM_SHA384\nECDHE-RSA-AES128-GCM-SHA256\nAES128-SHA\nRC4-SHA\nDES-CBC3-SHA"></textarea>' +
      '<div class="tk-btns"><button class="btn sm" id="ct-cs-grade">Grade Cipher Suites</button><button class="btn sm ghost" id="ct-cs-sample">Load Sample</button></div>' +
      '<div id="ct-cs-results" style="margin-top:12px"></div>';

    container.querySelector('#ct-cs-sample').onclick = function() {
      container.querySelector('#ct-cs-input').value = 'TLS_AES_256_GCM_SHA384\nTLS_AES_128_GCM_SHA256\nTLS_CHACHA20_POLY1305_SHA256\nECDHE-RSA-AES256-GCM-SHA384\nECDHE-RSA-AES128-GCM-SHA256\nECDHE-RSA-AES256-SHA384\nAES256-GCM-SHA384\nAES128-SHA\nDES-CBC3-SHA\nRC4-SHA\nRC4-MD5';
    };

    container.querySelector('#ct-cs-grade').onclick = function() {
      var lines = container.querySelector('#ct-cs-input').value.split('\n').map(function(l) { return l.trim(); }).filter(Boolean);
      if (lines.length === 0) return;
      var html = '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
        '<thead><tr style="border-bottom:2px solid var(--line)">' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Cipher Suite</th>' +
        '<th style="padding:6px;text-align:center;color:var(--mut)">Grade</th>' +
        '<th style="padding:6px;text-align:left;color:var(--mut)">Assessment</th>' +
        '</tr></thead><tbody>';
      lines.forEach(function(cs) {
        var info = CIPHER_GRADES[cs];
        var grade = info ? info.grade : '?';
        var note = info ? info.note : 'Unknown cipher suite. Manual review required.';
        var color = grade.startsWith('A') ? '#00e676' : grade === 'B+' || grade === 'B' ? '#ffd600' : grade === 'C' ? '#ff9100' : grade === 'D' || grade === 'F' ? '#ff1744' : 'var(--mut)';
        html += '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:6px;font-family:var(--mono,monospace);font-size:.75rem">' + esc(cs) + '</td>' +
          '<td style="padding:6px;text-align:center;font-weight:700;font-size:1rem;color:' + color + '">' + esc(grade) + '</td>' +
          '<td style="padding:6px;color:var(--mut)">' + esc(note) + '</td></tr>';
      });
      html += '</tbody></table></div>';
      var fCount = lines.filter(function(cs) { var i = CIPHER_GRADES[cs]; return i && i.grade === 'F'; }).length;
      if (fCount > 0) html += '<div style="margin-top:12px;padding:10px;background:rgba(255,23,68,0.1);border:1px solid rgba(255,23,68,0.3);border-radius:4px;font-size:.8rem;color:#ff1744"><strong>WARNING:</strong> ' + fCount + ' cipher suite(s) graded F. These must be disabled immediately.</div>';
      container.querySelector('#ct-cs-results').innerHTML = html;
    };
  }

  function renderKeysTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Key Size Recommendations</h2>' +
      '<p class="muted" style="margin-bottom:12px">NIST-aligned key size recommendations including post-quantum considerations.</p>' +
      '<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse;font-size:.78rem">' +
      '<thead><tr style="border-bottom:2px solid var(--line)">' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Algorithm</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Security Level</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Recommended</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Post-Quantum</th>' +
      '<th style="padding:8px;text-align:left;color:var(--mut)">Note</th>' +
      '</tr></thead><tbody>' +
      KEY_RECOMMENDATIONS.map(function(r) {
        return '<tr style="border-bottom:1px solid var(--line)">' +
          '<td style="padding:8px;font-weight:600;color:var(--acc)">' + esc(r.algorithm) + '</td>' +
          '<td style="padding:8px">' + esc(r.securityLevel) + '</td>' +
          '<td style="padding:8px;color:#00e676">' + esc(r.recommended) + '</td>' +
          '<td style="padding:8px;color:#ffd600">' + esc(r.postQuantum) + '</td>' +
          '<td style="padding:8px;color:var(--mut)">' + esc(r.note) + '</td></tr>';
      }).join('') +
      '</tbody></table></div>';
  }

  function renderAttacksTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Cryptographic Attack Reference</h2>' +
      '<p class="muted" style="margin-bottom:12px">' + CRYPTO_ATTACKS.length + ' documented attacks against cryptographic systems.</p>' +
      '<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:10px">' +
      CRYPTO_ATTACKS.map(function(a) {
        var sevColor = a.severity === 'Critical' ? '#ff1744' : a.severity === 'High' ? '#ff9100' : a.severity === 'Medium' ? '#ffd600' : a.severity === 'Future' ? '#d500f9' : 'var(--mut)';
        return '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px">' +
          '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">' +
            '<span style="font-weight:700;font-size:.85rem">' + esc(a.name) + '</span>' +
            '<span style="font-size:.6rem;color:' + sevColor + ';border:1px solid ' + sevColor + ';padding:1px 5px;border-radius:3px;font-weight:600">' + esc(a.severity) + '</span>' +
            (a.year !== 'N/A' ? '<span style="font-size:.65rem;color:var(--mut)">' + a.year + '</span>' : '') +
          '</div>' +
          '<div style="font-size:.72rem;color:var(--acc);margin-bottom:4px">Target: ' + esc(a.target) + '</div>' +
          '<div style="font-size:.76rem;color:var(--mut);margin-bottom:6px;line-height:1.5">' + esc(a.desc) + '</div>' +
          '<div style="font-size:.74rem;background:rgba(0,228,255,0.06);border:1px solid rgba(0,228,255,0.15);border-radius:4px;padding:6px"><strong style="color:var(--acc)">Mitigation:</strong> ' + esc(a.mitigation) + '</div>' +
          (a.cve !== 'N/A' ? '<div style="font-size:.65rem;color:var(--mut);margin-top:4px">' + esc(a.cve) + '</div>' : '') +
        '</div>';
      }).join('') +
      '</div>';
  }

  function renderDHTab(container) {
    container.innerHTML =
      '<h2 class="pg-h2">Diffie-Hellman Key Exchange Demo</h2>' +
      '<p class="muted" style="margin-bottom:12px">Interactive visualization of the DH key exchange. Both parties agree on a shared secret without ever transmitting it.</p>' +
      '<div style="display:grid;grid-template-columns:1fr auto 1fr;gap:16px;align-items:start">' +
        // Alice
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
          '<div style="font-weight:700;color:#00e5ff;margin-bottom:8px;text-align:center">Alice</div>' +
          '<div style="font-size:.78rem;margin-bottom:4px">Private key (a): <span id="ct-dh-a" style="color:var(--acc)">--</span></div>' +
          '<div style="font-size:.78rem">Public value (A = g^a mod p): <span id="ct-dh-A" style="color:#00e676">--</span></div>' +
          '<div style="font-size:.78rem;margin-top:8px">Shared secret (B^a mod p): <span id="ct-dh-sa" style="color:#ffd600;font-weight:700">--</span></div>' +
        '</div>' +
        // Arrow
        '<div style="display:flex;flex-direction:column;align-items:center;gap:8px;padding-top:40px">' +
          '<div style="font-size:.7rem;color:var(--mut)">Public</div>' +
          '<div style="color:var(--acc)">A --></div>' +
          '<div style="color:var(--acc)"><-- B</div>' +
          '<div style="font-size:.7rem;color:var(--mut)">p=' + '<span id="ct-dh-p">--</span>, g=<span id="ct-dh-g">--</span></div>' +
        '</div>' +
        // Bob
        '<div style="background:var(--card);border:1px solid var(--line);border-radius:6px;padding:16px">' +
          '<div style="font-weight:700;color:#ff9100;margin-bottom:8px;text-align:center">Bob</div>' +
          '<div style="font-size:.78rem;margin-bottom:4px">Private key (b): <span id="ct-dh-b" style="color:var(--acc)">--</span></div>' +
          '<div style="font-size:.78rem">Public value (B = g^b mod p): <span id="ct-dh-B" style="color:#00e676">--</span></div>' +
          '<div style="font-size:.78rem;margin-top:8px">Shared secret (A^b mod p): <span id="ct-dh-sb" style="color:#ffd600;font-weight:700">--</span></div>' +
        '</div>' +
      '</div>' +
      '<div style="text-align:center;margin-top:16px"><button class="btn sm" id="ct-dh-run">Run Key Exchange</button></div>' +
      '<div id="ct-dh-explain" style="margin-top:16px;font-size:.78rem;color:var(--mut);line-height:1.6"></div>';

    container.querySelector('#ct-dh-run').onclick = function() {
      // Use small numbers for demonstration
      var p = 23; // prime
      var g = 5;  // generator
      var a = Math.floor(Math.random() * 20) + 2; // Alice's private
      var b = Math.floor(Math.random() * 20) + 2; // Bob's private
      var A = modPow(g, a, p); // Alice's public
      var B = modPow(g, b, p); // Bob's public
      var sa = modPow(B, a, p); // Alice's shared secret
      var sb = modPow(A, b, p); // Bob's shared secret

      container.querySelector('#ct-dh-p').textContent = p;
      container.querySelector('#ct-dh-g').textContent = g;
      container.querySelector('#ct-dh-a').textContent = a;
      container.querySelector('#ct-dh-b').textContent = b;
      container.querySelector('#ct-dh-A').textContent = A;
      container.querySelector('#ct-dh-B').textContent = B;
      container.querySelector('#ct-dh-sa').textContent = sa;
      container.querySelector('#ct-dh-sb').textContent = sb;

      var match = sa === sb;
      container.querySelector('#ct-dh-explain').innerHTML =
        '<strong>How it works:</strong><br>' +
        '1. Alice and Bob agree on public parameters: p=' + p + ' (prime), g=' + g + ' (generator)<br>' +
        '2. Alice picks private key a=' + a + ', computes A = ' + g + '^' + a + ' mod ' + p + ' = ' + A + '<br>' +
        '3. Bob picks private key b=' + b + ', computes B = ' + g + '^' + b + ' mod ' + p + ' = ' + B + '<br>' +
        '4. They exchange A and B publicly<br>' +
        '5. Alice computes: B^a mod p = ' + B + '^' + a + ' mod ' + p + ' = <strong style="color:#ffd600">' + sa + '</strong><br>' +
        '6. Bob computes: A^b mod p = ' + A + '^' + b + ' mod ' + p + ' = <strong style="color:#ffd600">' + sb + '</strong><br>' +
        '<br><strong style="color:' + (match ? '#00e676' : '#ff1744') + '">Shared secrets ' + (match ? 'MATCH' : 'DO NOT MATCH') + ': ' + sa + '</strong><br>' +
        '<br>An eavesdropper sees p, g, A, and B — but computing the shared secret requires solving the discrete logarithm problem, which is computationally infeasible for large primes (2048+ bits in practice).';
    };
  }

  function modPow(base, exp, mod) {
    var result = 1;
    base = base % mod;
    while (exp > 0) {
      if (exp % 2 === 1) result = (result * base) % mod;
      exp = Math.floor(exp / 2);
      base = (base * base) % mod;
    }
    return result;
  }

  render();
}
