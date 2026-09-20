// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Crypto Playground — interactive cryptography learning tool with visual demos.

export function renderCryptoPlayground(container) {

  let activeTab = "caesar";

  // Caesar cipher
  function caesarEncrypt(text, shift) {
    return text.split("").map(c => {
      if (c >= "a" && c <= "z") return String.fromCharCode(((c.charCodeAt(0) - 97 + shift) % 26 + 26) % 26 + 97);
      if (c >= "A" && c <= "Z") return String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26 + 26) % 26 + 65);
      return c;
    }).join("");
  }

  function caesarBruteForce(cipher) {
    return Array.from({ length: 26 }, (_, i) => ({ shift: i, text: caesarEncrypt(cipher, -i) }));
  }

  // Vigenere cipher
  function vigenereEncrypt(text, key, decrypt) {
    const k = key.toLowerCase().replace(/[^a-z]/g, "");
    if (!k) return text;
    let ki = 0;
    return text.split("").map(c => {
      if (c >= "a" && c <= "z") {
        const shift = decrypt ? -(k.charCodeAt(ki % k.length) - 97) : (k.charCodeAt(ki % k.length) - 97);
        ki++;
        return String.fromCharCode(((c.charCodeAt(0) - 97 + shift) % 26 + 26) % 26 + 97);
      }
      if (c >= "A" && c <= "Z") {
        const shift = decrypt ? -(k.charCodeAt(ki % k.length) - 97) : (k.charCodeAt(ki % k.length) - 97);
        ki++;
        return String.fromCharCode(((c.charCodeAt(0) - 65 + shift) % 26 + 26) % 26 + 65);
      }
      return c;
    }).join("");
  }

  // XOR cipher
  function xorEncrypt(text, keyBytes) {
    const input = new TextEncoder().encode(text);
    const output = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) output[i] = input[i] ^ keyBytes[i % keyBytes.length];
    return output;
  }

  function bytesToHex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join(" "); }
  function hexToBytes(hex) { return new Uint8Array(hex.replace(/\s/g, "").match(/.{2}/g).map(b => parseInt(b, 16))); }

  // RSA demo (small numbers only)
  function isPrime(n) { if (n < 2) return false; for (let i = 2; i * i <= n; i++) if (n % i === 0) return false; return true; }
  function gcd(a, b) { while (b) { [a, b] = [b, a % b]; } return a; }
  function modInverse(e, phi) {
    let [old_r, r] = [phi, e], [old_s, s] = [0, 1];
    while (r !== 0) { const q = Math.floor(old_r / r); [old_r, r] = [r, old_r - q * r]; [old_s, s] = [s, old_s - q * s]; }
    return ((old_s % phi) + phi) % phi;
  }
  function modPow(base, exp, mod) {
    let result = 1; base = base % mod;
    while (exp > 0) { if (exp % 2 === 1) result = (result * base) % mod; exp = Math.floor(exp / 2); base = (base * base) % mod; }
    return result;
  }
  function generateRSA(p, q) {
    if (!isPrime(p) || !isPrime(q) || p === q) return null;
    const n = p * q, phi = (p - 1) * (q - 1);
    let e = 65537;
    if (e >= phi) { for (e = 3; e < phi; e += 2) if (gcd(e, phi) === 1) break; }
    if (gcd(e, phi) !== 1) { for (e = 3; e < phi; e++) if (gcd(e, phi) === 1) break; }
    const d = modInverse(e, phi);
    return { p, q, n, phi, e, d };
  }

  // Diffie-Hellman demo
  function dhDemo(p, g, a, b) {
    const A = modPow(g, a, p);
    const B = modPow(g, b, p);
    const sharedA = modPow(B, a, p);
    const sharedB = modPow(A, b, p);
    return { p, g, a, b, A, B, sharedA, sharedB, match: sharedA === sharedB };
  }

  // Frequency analysis
  function frequencyAnalysis(text) {
    const counts = {};
    let total = 0;
    for (const c of text.toLowerCase()) {
      if (c >= "a" && c <= "z") { counts[c] = (counts[c] || 0) + 1; total++; }
    }
    const english = { e: 12.7, t: 9.1, a: 8.2, o: 7.5, i: 7.0, n: 6.7, s: 6.3, h: 6.1, r: 6.0, d: 4.3, l: 4.0, c: 2.8, u: 2.8, m: 2.4, w: 2.4, f: 2.2, g: 2.0, y: 2.0, p: 1.9, b: 1.5, v: 1.0, k: 0.8, j: 0.15, x: 0.15, q: 0.10, z: 0.07 };
    const freq = {};
    for (let i = 0; i < 26; i++) {
      const c = String.fromCharCode(97 + i);
      freq[c] = { count: counts[c] || 0, pct: total ? ((counts[c] || 0) / total * 100) : 0, english: english[c] || 0 };
    }
    return { freq, total };
  }

  // Hash visualization (simple non-crypto hash for demo — real SHA uses SubtleCrypto)
  function simpleHash(text) {
    let h = 0;
    for (let i = 0; i < text.length; i++) { h = ((h << 5) - h + text.charCodeAt(i)) | 0; }
    return (h >>> 0).toString(16).padStart(8, "0");
  }

  async function sha256(text) {
    try {
      const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (_) { return "SubtleCrypto not available"; }
  }

  async function sha1(text) {
    try {
      const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(text));
      return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
    } catch (_) { return "SubtleCrypto not available"; }
  }

  const TABS = [
    { id: "caesar", label: "Caesar" },
    { id: "vigenere", label: "Vigenère" },
    { id: "xor", label: "XOR" },
    { id: "rsa", label: "RSA" },
    { id: "dh", label: "Diffie-Hellman" },
    { id: "hash", label: "Hashing" },
    { id: "frequency", label: "Frequency" },
  ];

  function render() {
    container.innerHTML = `
      <style>
        .cp-wrap{font-family:system-ui,sans-serif;color:#e0e0e0;max-width:1000px;margin:0 auto;padding:20px}
        .cp-h1{font-size:1.6rem;font-weight:700;color:#00d4ff;margin:0 0 6px}
        .cp-sub{color:#888;font-size:.85rem;margin:0 0 20px}
        .cp-tabs{display:flex;gap:4px;margin-bottom:20px;border-bottom:1px solid #333;flex-wrap:wrap}
        .cp-tab{padding:8px 14px;cursor:pointer;color:#888;border:none;background:none;font-size:.82rem;border-bottom:2px solid transparent;transition:all .2s}
        .cp-tab:hover{color:#ccc}
        .cp-tab.active{color:#00d4ff;border-bottom-color:#00d4ff}
        .cp-card{background:#111;border:1px solid #222;border-radius:8px;padding:16px;margin-bottom:16px}
        .cp-card h3{margin:0 0 10px;font-size:1rem;color:#00d4ff}
        .cp-input{background:#0a0a0a;border:1px solid #333;color:#e0e0e0;padding:8px 12px;border-radius:4px;font-family:monospace;font-size:.85rem;width:100%}
        .cp-input:focus{outline:none;border-color:#00d4ff}
        .cp-btn{background:#00d4ff;color:#000;border:none;padding:6px 14px;border-radius:4px;cursor:pointer;font-size:.8rem;font-weight:600}
        .cp-btn:hover{opacity:.85}
        .cp-result{background:#0a0f14;border:1px solid #00d4ff33;border-radius:6px;padding:12px;margin:8px 0;font-family:monospace;font-size:.85rem;word-break:break-all}
        .cp-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid #1a1a1a}
        .cp-label{color:#888;font-size:.82rem}
        .cp-val{font-family:monospace;color:#e0e0e0;font-size:.82rem}
        .cp-steps{background:#0a0a0a;border-radius:4px;padding:12px;font-size:.82rem;line-height:1.6}
        .cp-step{color:#888;margin:2px 0}
        .cp-step b{color:#00d4ff}
        .cp-bar-wrap{display:flex;align-items:end;gap:2px;height:120px;margin:8px 0}
        .cp-bar{width:100%;border-radius:2px 2px 0 0;transition:height .3s;position:relative;min-width:12px}
        .cp-bar span{position:absolute;bottom:-18px;left:50%;transform:translateX(-50%);font-size:.65rem;color:#888}
        .cp-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
        @media(max-width:768px){.cp-grid{grid-template-columns:1fr}}
        .cp-scroll{max-height:300px;overflow-y:auto}
        .cp-table{width:100%;border-collapse:collapse;font-size:.8rem}
        .cp-table td{padding:4px 8px;border-bottom:1px solid #1a1a1a;font-family:monospace}
        .cp-table td:first-child{color:#00d4ff;text-align:center;width:40px}
      </style>
      <div class="cp-wrap">
        <h1 class="cp-h1">Crypto Playground</h1>
        <p class="cp-sub">Interactive cryptography demos — learn by doing</p>
        <div class="cp-tabs">
          ${TABS.map(t => `<button class="cp-tab ${activeTab === t.id ? "active" : ""}" data-tab="${t.id}">${t.label}</button>`).join("")}
        </div>
        <div id="cp-content"></div>
      </div>`;
    container.querySelectorAll(".cp-tab").forEach(tab => { tab.onclick = () => { activeTab = tab.dataset.tab; render(); }; });
    const content = container.querySelector("#cp-content");
    const renderers = { caesar: renderCaesar, vigenere: renderVigenere, xor: renderXor, rsa: renderRsa, dh: renderDH, hash: renderHash, frequency: renderFrequency };
    (renderers[activeTab] || renderCaesar)(content);
  }

  function renderCaesar(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>Caesar Cipher</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">Each letter is shifted by a fixed number of positions in the alphabet. One of the oldest known ciphers, used by Julius Caesar.</p>
        <textarea class="cp-input" id="cp-caesar-input" rows="2" placeholder="Enter plaintext...">The quick brown fox jumps over the lazy dog</textarea>
        <div style="display:flex;align-items:center;gap:12px;margin:10px 0">
          <label style="color:#888;font-size:.82rem">Shift:</label>
          <input type="range" id="cp-caesar-shift" min="0" max="25" value="13" style="flex:1">
          <span id="cp-caesar-shift-val" style="color:#00d4ff;font-weight:700;width:30px;text-align:center">13</span>
        </div>
        <div class="cp-result" id="cp-caesar-result"></div>
      </div>
      <div class="cp-card">
        <h3>Brute Force (all 26 shifts)</h3>
        <div class="cp-scroll" id="cp-caesar-brute"></div>
      </div>`;
    const input = el.querySelector("#cp-caesar-input");
    const slider = el.querySelector("#cp-caesar-shift");
    const valSpan = el.querySelector("#cp-caesar-shift-val");
    const result = el.querySelector("#cp-caesar-result");
    const brute = el.querySelector("#cp-caesar-brute");
    function update() {
      const shift = parseInt(slider.value, 10);
      valSpan.textContent = shift;
      const enc = caesarEncrypt(input.value, shift);
      result.innerHTML = `<span style="color:#888">Encrypted (ROT-${shift}):</span><br><span style="color:#00d4ff">${enc}</span>`;
      const bf = caesarBruteForce(enc);
      brute.innerHTML = `<table class="cp-table">${bf.map(r =>
        `<tr style="${r.shift === shift ? "background:#00d4ff15" : ""}"><td>ROT-${r.shift}</td><td>${r.text}</td></tr>`
      ).join("")}</table>`;
    }
    slider.oninput = update;
    input.oninput = update;
    update();
  }

  function renderVigenere(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>Vigenère Cipher</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">A polyalphabetic cipher that uses a keyword to shift each letter by a different amount, making frequency analysis harder.</p>
        <textarea class="cp-input" id="cp-vig-input" rows="2" placeholder="Enter text...">Attack at dawn</textarea>
        <div style="margin:8px 0"><input class="cp-input" id="cp-vig-key" placeholder="Key (e.g. SECRET)" value="LEMON" style="max-width:300px"></div>
        <div style="display:flex;gap:8px">
          <button class="cp-btn" id="cp-vig-enc">Encrypt</button>
          <button class="cp-btn" id="cp-vig-dec" style="background:#333;color:#e0e0e0">Decrypt</button>
        </div>
        <div class="cp-result" id="cp-vig-result"></div>
      </div>`;
    const input = el.querySelector("#cp-vig-input");
    const key = el.querySelector("#cp-vig-key");
    const result = el.querySelector("#cp-vig-result");
    el.querySelector("#cp-vig-enc").onclick = () => {
      const enc = vigenereEncrypt(input.value, key.value, false);
      result.innerHTML = `<span style="color:#888">Encrypted:</span><br><span style="color:#00d4ff">${enc}</span>`;
    };
    el.querySelector("#cp-vig-dec").onclick = () => {
      const dec = vigenereEncrypt(input.value, key.value, true);
      result.innerHTML = `<span style="color:#888">Decrypted:</span><br><span style="color:#17a34a">${dec}</span>`;
    };
  }

  function renderXor(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>XOR Cipher</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">XOR is symmetric — encrypting twice with the same key returns the original. Widely used as a building block in modern encryption.</p>
        <textarea class="cp-input" id="cp-xor-input" rows="2" placeholder="Enter plaintext...">Hello World</textarea>
        <div style="margin:8px 0"><input class="cp-input" id="cp-xor-key" placeholder="Key (text or hex like 0x41)" value="K" style="max-width:300px"></div>
        <button class="cp-btn" id="cp-xor-btn">XOR Encrypt/Decrypt</button>
        <div class="cp-result" id="cp-xor-result"></div>
      </div>
      <div class="cp-card">
        <h3>Single-Byte XOR Brute Force</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">Paste hex-encoded ciphertext to try all 256 single-byte keys.</p>
        <input class="cp-input" id="cp-xor-brute-input" placeholder="Hex ciphertext (e.g. 03 27 21 21 20 65 18 20 23 21 29)">
        <button class="cp-btn" style="margin-top:8px" id="cp-xor-brute-btn">Brute Force</button>
        <div class="cp-scroll" id="cp-xor-brute-result" style="margin-top:8px"></div>
      </div>`;
    el.querySelector("#cp-xor-btn").onclick = () => {
      const text = el.querySelector("#cp-xor-input").value;
      const keyStr = el.querySelector("#cp-xor-key").value;
      const keyBytes = keyStr.startsWith("0x") ? [parseInt(keyStr, 16)] : new TextEncoder().encode(keyStr);
      const enc = xorEncrypt(text, keyBytes);
      const hexOut = bytesToHex(enc);
      const dec = new TextDecoder().decode(xorEncrypt(new TextDecoder().decode(enc), keyBytes));
      el.querySelector("#cp-xor-result").innerHTML = `
        <div class="cp-row"><span class="cp-label">Hex output</span><span class="cp-val" style="color:#00d4ff">${hexOut}</span></div>
        <div class="cp-row"><span class="cp-label">XOR back (verify)</span><span class="cp-val" style="color:#17a34a">${dec}</span></div>`;
    };
    el.querySelector("#cp-xor-brute-btn").onclick = () => {
      const hex = el.querySelector("#cp-xor-brute-input").value;
      const bytes = hexToBytes(hex);
      const results = [];
      for (let k = 0; k < 256; k++) {
        const dec = new Uint8Array(bytes.length);
        for (let i = 0; i < bytes.length; i++) dec[i] = bytes[i] ^ k;
        const text = new TextDecoder("utf-8", { fatal: false }).decode(dec);
        const printable = text.split("").filter(c => c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126).length / text.length;
        if (printable > 0.8) results.push({ key: k, text });
      }
      el.querySelector("#cp-xor-brute-result").innerHTML = results.length ?
        `<table class="cp-table">${results.map(r => `<tr><td>0x${r.key.toString(16).padStart(2, "0")}</td><td>${r.text.replace(/</g, "&lt;")}</td></tr>`).join("")}</table>` :
        `<p style="color:#888">No printable results found</p>`;
    };
  }

  function renderRsa(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>RSA Demo</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">RSA uses two large primes to create a public/private key pair. This demo uses small primes for educational purposes.</p>
        <div class="cp-grid">
          <div>
            <label style="color:#888;font-size:.8rem">Prime p:</label>
            <input class="cp-input" id="cp-rsa-p" type="number" value="61">
          </div>
          <div>
            <label style="color:#888;font-size:.8rem">Prime q:</label>
            <input class="cp-input" id="cp-rsa-q" type="number" value="53">
          </div>
        </div>
        <button class="cp-btn" style="margin-top:10px" id="cp-rsa-gen">Generate Keys</button>
        <div id="cp-rsa-keys"></div>
      </div>
      <div class="cp-card">
        <h3>Encrypt / Decrypt</h3>
        <div style="display:flex;gap:8px;align-items:end">
          <div style="flex:1"><label style="color:#888;font-size:.8rem">Message (number):</label><input class="cp-input" id="cp-rsa-msg" type="number" value="42"></div>
          <button class="cp-btn" id="cp-rsa-enc">Encrypt</button>
          <button class="cp-btn" id="cp-rsa-dec" style="background:#333;color:#e0e0e0">Decrypt</button>
        </div>
        <div class="cp-result" id="cp-rsa-result"></div>
      </div>`;
    let keys = null;
    el.querySelector("#cp-rsa-gen").onclick = () => {
      const p = parseInt(el.querySelector("#cp-rsa-p").value, 10);
      const q = parseInt(el.querySelector("#cp-rsa-q").value, 10);
      keys = generateRSA(p, q);
      if (!keys) { el.querySelector("#cp-rsa-keys").innerHTML = `<p style="color:#ef4444;margin-top:8px">Both values must be different primes.</p>`; return; }
      el.querySelector("#cp-rsa-keys").innerHTML = `
        <div class="cp-steps" style="margin-top:10px">
          <div class="cp-step"><b>Step 1:</b> Choose primes: p = ${keys.p}, q = ${keys.q}</div>
          <div class="cp-step"><b>Step 2:</b> n = p × q = ${keys.p} × ${keys.q} = <b>${keys.n}</b></div>
          <div class="cp-step"><b>Step 3:</b> φ(n) = (p-1)(q-1) = ${keys.p - 1} × ${keys.q - 1} = <b>${keys.phi}</b></div>
          <div class="cp-step"><b>Step 4:</b> Choose e where gcd(e, φ) = 1: e = <b>${keys.e}</b></div>
          <div class="cp-step"><b>Step 5:</b> d = e⁻¹ mod φ = ${keys.e}⁻¹ mod ${keys.phi} = <b>${keys.d}</b></div>
          <div class="cp-step" style="margin-top:8px;color:#00d4ff"><b>Public Key:</b> (e=${keys.e}, n=${keys.n})</div>
          <div class="cp-step" style="color:#ef4444"><b>Private Key:</b> (d=${keys.d}, n=${keys.n})</div>
        </div>`;
    };
    el.querySelector("#cp-rsa-enc").onclick = () => {
      if (!keys) return;
      const m = parseInt(el.querySelector("#cp-rsa-msg").value, 10);
      if (m >= keys.n) { el.querySelector("#cp-rsa-result").innerHTML = `<p style="color:#ef4444">Message must be less than n (${keys.n})</p>`; return; }
      const c = modPow(m, keys.e, keys.n);
      el.querySelector("#cp-rsa-result").innerHTML = `
        <div class="cp-step"><b>Encrypt:</b> c = m<sup>e</sup> mod n = ${m}<sup>${keys.e}</sup> mod ${keys.n} = <b style="color:#00d4ff">${c}</b></div>`;
    };
    el.querySelector("#cp-rsa-dec").onclick = () => {
      if (!keys) return;
      const m = parseInt(el.querySelector("#cp-rsa-msg").value, 10);
      const c = modPow(m, keys.e, keys.n);
      const dec = modPow(c, keys.d, keys.n);
      el.querySelector("#cp-rsa-result").innerHTML = `
        <div class="cp-step"><b>Encrypt:</b> c = ${m}<sup>${keys.e}</sup> mod ${keys.n} = <b style="color:#00d4ff">${c}</b></div>
        <div class="cp-step"><b>Decrypt:</b> m = c<sup>d</sup> mod n = ${c}<sup>${keys.d}</sup> mod ${keys.n} = <b style="color:#17a34a">${dec}</b></div>
        <div class="cp-step" style="color:${dec === m ? "#17a34a" : "#ef4444"}">${dec === m ? "✓ Decryption matches original!" : "✗ Mismatch!"}</div>`;
    };
  }

  function renderDH(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>Diffie-Hellman Key Exchange</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">Two parties agree on a shared secret over an insecure channel, without ever transmitting the secret itself.</p>
        <div class="cp-grid">
          <div>
            <label style="color:#888;font-size:.8rem">Prime (p):</label>
            <input class="cp-input" id="cp-dh-p" type="number" value="23">
          </div>
          <div>
            <label style="color:#888;font-size:.8rem">Generator (g):</label>
            <input class="cp-input" id="cp-dh-g" type="number" value="5">
          </div>
          <div>
            <label style="color:#888;font-size:.8rem">Alice's secret (a):</label>
            <input class="cp-input" id="cp-dh-a" type="number" value="6">
          </div>
          <div>
            <label style="color:#888;font-size:.8rem">Bob's secret (b):</label>
            <input class="cp-input" id="cp-dh-b" type="number" value="15">
          </div>
        </div>
        <button class="cp-btn" style="margin-top:10px" id="cp-dh-btn">Compute</button>
        <div id="cp-dh-result"></div>
      </div>`;
    el.querySelector("#cp-dh-btn").onclick = () => {
      const p = parseInt(el.querySelector("#cp-dh-p").value, 10);
      const g = parseInt(el.querySelector("#cp-dh-g").value, 10);
      const a = parseInt(el.querySelector("#cp-dh-a").value, 10);
      const b = parseInt(el.querySelector("#cp-dh-b").value, 10);
      const r = dhDemo(p, g, a, b);
      el.querySelector("#cp-dh-result").innerHTML = `
        <div class="cp-steps" style="margin-top:10px">
          <div class="cp-step"><b>Public parameters:</b> p = ${r.p}, g = ${r.g}</div>
          <div class="cp-step" style="margin-top:6px"><b>Alice:</b> secret a = ${r.a}, sends A = g<sup>a</sup> mod p = ${r.g}<sup>${r.a}</sup> mod ${r.p} = <b style="color:#00d4ff">${r.A}</b></div>
          <div class="cp-step"><b>Bob:</b> secret b = ${r.b}, sends B = g<sup>b</sup> mod p = ${r.g}<sup>${r.b}</sup> mod ${r.p} = <b style="color:#00d4ff">${r.B}</b></div>
          <div class="cp-step" style="margin-top:6px"><b>Alice computes:</b> B<sup>a</sup> mod p = ${r.B}<sup>${r.a}</sup> mod ${r.p} = <b style="color:#17a34a">${r.sharedA}</b></div>
          <div class="cp-step"><b>Bob computes:</b> A<sup>b</sup> mod p = ${r.A}<sup>${r.b}</sup> mod ${r.p} = <b style="color:#17a34a">${r.sharedB}</b></div>
          <div class="cp-step" style="margin-top:6px;color:${r.match ? "#17a34a" : "#ef4444"}"><b>Shared secret: ${r.sharedA}</b> ${r.match ? "✓ Both sides match!" : "✗ Mismatch!"}</div>
          <div class="cp-step" style="color:#888;margin-top:8px">An eavesdropper sees p=${r.p}, g=${r.g}, A=${r.A}, B=${r.B} — but cannot compute the shared secret without solving the discrete logarithm problem.</div>
        </div>`;
    };
  }

  function renderHash(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>Hash Functions</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">Hash functions map arbitrary input to a fixed-size output. Even a tiny change in input completely changes the hash (avalanche effect).</p>
        <textarea class="cp-input" id="cp-hash-input" rows="2" placeholder="Enter text to hash...">Hello World</textarea>
        <button class="cp-btn" style="margin-top:8px" id="cp-hash-btn">Compute Hashes</button>
        <div id="cp-hash-result"></div>
      </div>
      <div class="cp-card">
        <h3>Avalanche Effect Demo</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 8px">Change one character and see how the hash completely changes.</p>
        <div class="cp-grid">
          <div><label style="color:#888;font-size:.75rem">Input A:</label><input class="cp-input" id="cp-av-a" value="hello"></div>
          <div><label style="color:#888;font-size:.75rem">Input B:</label><input class="cp-input" id="cp-av-b" value="hellp"></div>
        </div>
        <button class="cp-btn" style="margin-top:8px" id="cp-av-btn">Compare</button>
        <div id="cp-av-result"></div>
      </div>`;
    el.querySelector("#cp-hash-btn").onclick = async () => {
      const text = el.querySelector("#cp-hash-input").value;
      const s256 = await sha256(text);
      const s1 = await sha1(text);
      el.querySelector("#cp-hash-result").innerHTML = `<div class="cp-result">
        <div class="cp-row"><span class="cp-label">SHA-256</span><span class="cp-val" style="font-size:.72rem;color:#00d4ff">${s256}</span></div>
        <div class="cp-row"><span class="cp-label">SHA-1</span><span class="cp-val" style="font-size:.75rem">${s1}</span></div>
        <div class="cp-row"><span class="cp-label">Length (bytes)</span><span class="cp-val">SHA-256: 32 | SHA-1: 20</span></div>
      </div>`;
    };
    el.querySelector("#cp-av-btn").onclick = async () => {
      const a = el.querySelector("#cp-av-a").value;
      const b = el.querySelector("#cp-av-b").value;
      const ha = await sha256(a), hb = await sha256(b);
      let diff = 0;
      for (let i = 0; i < Math.min(ha.length, hb.length); i++) if (ha[i] !== hb[i]) diff++;
      const pct = (diff / ha.length * 100).toFixed(1);
      el.querySelector("#cp-av-result").innerHTML = `<div class="cp-result">
        <div class="cp-row"><span class="cp-label">"${a}"</span><span class="cp-val" style="font-size:.7rem;color:#00d4ff">${ha}</span></div>
        <div class="cp-row"><span class="cp-label">"${b}"</span><span class="cp-val" style="font-size:.7rem;color:#f59e0b">${hb}</span></div>
        <div class="cp-row"><span class="cp-label">Characters different</span><span class="cp-val">${diff} of ${ha.length} (${pct}%)</span></div>
        <p style="color:#888;font-size:.8rem;margin:8px 0 0">Changing just "${a}" → "${b}" changed ${pct}% of the hash output — this is the <strong style="color:#00d4ff">avalanche effect</strong>.</p>
      </div>`;
    };
  }

  function renderFrequency(el) {
    el.innerHTML = `
      <div class="cp-card">
        <h3>Frequency Analysis</h3>
        <p style="color:#888;font-size:.82rem;margin:0 0 10px">Compare letter frequencies in ciphertext to standard English. Peaks that don't align with E-T-A-O suggest substitution.</p>
        <textarea class="cp-input" id="cp-freq-input" rows="4" placeholder="Paste ciphertext here...">Gur dhvpx oebja sbk whzcf bire gur ynml qbt</textarea>
        <button class="cp-btn" style="margin-top:8px" id="cp-freq-btn">Analyze</button>
        <div id="cp-freq-result"></div>
      </div>`;
    el.querySelector("#cp-freq-btn").onclick = () => {
      const text = el.querySelector("#cp-freq-input").value;
      const { freq, total } = frequencyAnalysis(text);
      const maxPct = Math.max(...Object.values(freq).map(f => Math.max(f.pct, f.english)));
      el.querySelector("#cp-freq-result").innerHTML = `
        <div class="cp-result">
          <p style="color:#888;font-size:.8rem;margin:0 0 8px">${total} letters analyzed</p>
          <div style="display:flex;gap:2px;align-items:end;height:140px;padding-bottom:20px">
            ${Object.entries(freq).map(([c, f]) => {
              const h1 = maxPct ? (f.pct / maxPct * 120) : 0;
              const h2 = maxPct ? (f.english / maxPct * 120) : 0;
              return `<div style="flex:1;display:flex;flex-direction:column;align-items:center;position:relative;height:100%">
                <div style="display:flex;gap:1px;align-items:end;height:120px;width:100%">
                  <div style="flex:1;height:${h1}px;background:#00d4ff;border-radius:1px 1px 0 0;opacity:.8"></div>
                  <div style="flex:1;height:${h2}px;background:#ef4444;border-radius:1px 1px 0 0;opacity:.4"></div>
                </div>
                <span style="font-size:.6rem;color:#888;margin-top:2px">${c}</span>
              </div>`;
            }).join("")}
          </div>
          <div style="display:flex;gap:16px;font-size:.75rem;color:#888;margin-top:4px">
            <span><span style="display:inline-block;width:10px;height:10px;background:#00d4ff;border-radius:1px;vertical-align:middle;margin-right:4px"></span>Input text</span>
            <span><span style="display:inline-block;width:10px;height:10px;background:#ef4444;opacity:.5;border-radius:1px;vertical-align:middle;margin-right:4px"></span>English average</span>
          </div>
        </div>`;
    };
  }

  render();
}
