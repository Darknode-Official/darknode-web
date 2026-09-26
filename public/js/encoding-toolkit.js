// Encoding Toolkit — Comprehensive encoder/decoder/converter.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── Encoders/Decoders ──

var ENCODINGS = {
  base64: {
    name: "Base64",
    encode: function(s) { return btoa(unescape(encodeURIComponent(s))); },
    decode: function(s) { try { return decodeURIComponent(escape(atob(s.trim()))); } catch(e) { return "[decode error: " + e.message + "]"; } }
  },
  base32: {
    name: "Base32",
    encode: function(s) {
      var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      var bytes = new TextEncoder().encode(s);
      var bits = "";
      for (var j = 0; j < bytes.length; j++) bits += bytes[j].toString(2).padStart(8, "0");
      while (bits.length % 5 !== 0) bits += "0";
      var out = "";
      for (var k = 0; k < bits.length; k += 5) out += alphabet[parseInt(bits.substring(k, k + 5), 2)];
      while (out.length % 8 !== 0) out += "=";
      return out;
    },
    decode: function(s) {
      var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
      var cleaned = s.trim().replace(/=+$/, "").toUpperCase();
      var bits = "";
      for (var i = 0; i < cleaned.length; i++) {
        var idx = alphabet.indexOf(cleaned[i]);
        if (idx < 0) continue;
        bits += idx.toString(2).padStart(5, "0");
      }
      var bytes = [];
      for (var j = 0; j + 7 < bits.length; j += 8) bytes.push(parseInt(bits.substring(j, j + 8), 2));
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
  },
  hex: {
    name: "Hex (Base16)",
    encode: function(s) {
      var bytes = new TextEncoder().encode(s);
      var out = [];
      for (var i = 0; i < bytes.length; i++) out.push(bytes[i].toString(16).padStart(2, "0"));
      return out.join(" ");
    },
    decode: function(s) {
      var hex = s.trim().replace(/\s+/g, "").replace(/0x/gi, "");
      var bytes = [];
      for (var i = 0; i + 1 < hex.length; i += 2) bytes.push(parseInt(hex.substring(i, i + 2), 16));
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
  },
  url: {
    name: "URL Encoding",
    encode: function(s) { return encodeURIComponent(s); },
    decode: function(s) { try { return decodeURIComponent(s.trim()); } catch(e) { return "[decode error]"; } }
  },
  html: {
    name: "HTML Entities",
    encode: function(s) {
      return s.replace(/[&<>"'\/\\]/g, function(c) {
        var map = { "&":"&amp;", "<":"&lt;", ">":"&gt;", '"':"&quot;", "'":"&#39;", "/":"&#47;", "\\":"\\" };
        return map[c] || "&#" + c.charCodeAt(0) + ";";
      });
    },
    decode: function(s) {
      var el = document.createElement("textarea");
      el.innerHTML = s;
      return el.value;
    }
  },
  unicode: {
    name: "Unicode Escapes",
    encode: function(s) {
      var out = [];
      for (var i = 0; i < s.length; i++) out.push("\\u" + s.charCodeAt(i).toString(16).padStart(4, "0"));
      return out.join("");
    },
    decode: function(s) {
      return s.replace(/\\u([0-9a-fA-F]{4})/g, function(_, h) { return String.fromCharCode(parseInt(h, 16)); });
    }
  },
  binary: {
    name: "Binary (8-bit)",
    encode: function(s) {
      var bytes = new TextEncoder().encode(s);
      var out = [];
      for (var i = 0; i < bytes.length; i++) out.push(bytes[i].toString(2).padStart(8, "0"));
      return out.join(" ");
    },
    decode: function(s) {
      var bytes = s.trim().split(/\s+/).filter(Boolean).map(function(b) { return parseInt(b, 2) & 0xFF; });
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
  },
  octal: {
    name: "Octal",
    encode: function(s) {
      var bytes = new TextEncoder().encode(s);
      var out = [];
      for (var i = 0; i < bytes.length; i++) out.push(bytes[i].toString(8).padStart(3, "0"));
      return out.join(" ");
    },
    decode: function(s) {
      var bytes = s.trim().split(/\s+/).filter(Boolean).map(function(o) { return parseInt(o, 8) & 0xFF; });
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
  },
  decimal: {
    name: "Decimal",
    encode: function(s) {
      var bytes = new TextEncoder().encode(s);
      var out = [];
      for (var i = 0; i < bytes.length; i++) out.push(bytes[i].toString());
      return out.join(" ");
    },
    decode: function(s) {
      var bytes = s.trim().split(/\s+/).filter(Boolean).map(function(d) { return parseInt(d, 10) & 0xFF; });
      return new TextDecoder().decode(new Uint8Array(bytes));
    }
  },
  rot13: {
    name: "ROT13",
    encode: function(s) {
      return s.replace(/[a-zA-Z]/g, function(c) {
        var base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
      });
    },
    decode: function(s) { return ENCODINGS.rot13.encode(s); }
  },
  rot47: {
    name: "ROT47",
    encode: function(s) {
      return s.replace(/[!-~]/g, function(c) {
        return String.fromCharCode(((c.charCodeAt(0) - 33 + 47) % 94) + 33);
      });
    },
    decode: function(s) { return ENCODINGS.rot47.encode(s); }
  },
  atbash: {
    name: "Atbash",
    encode: function(s) {
      return s.replace(/[a-zA-Z]/g, function(c) {
        var base = c <= "Z" ? 65 : 97;
        return String.fromCharCode(base + 25 - (c.charCodeAt(0) - base));
      });
    },
    decode: function(s) { return ENCODINGS.atbash.encode(s); }
  },
  morse: {
    name: "Morse Code",
    encode: function(s) {
      var map = {"A":".-","B":"-...","C":"-.-.","D":"-..","E":".","F":"..-.","G":"--.","H":"....","I":"..","J":".---","K":"-.-","L":".-..","M":"--","N":"-.","O":"---","P":".--.","Q":"--.-","R":".-.","S":"...","T":"-","U":"..-","V":"...-","W":".--","X":"-..-","Y":"-.--","Z":"--..","0":"-----","1":".----","2":"..---","3":"...--","4":"....-","5":".....","6":"-....","7":"--...","8":"---..","9":"----.",".":" .-.-.-",",":" --..--","?":" ..--.."," ":" / "};
      return s.toUpperCase().split("").map(function(c) { return map[c] || c; }).join(" ");
    },
    decode: function(s) {
      var map = {".-":"A","-...":"B","-.-.":"C","-..":"D",".":"E","..-.":"F","--.":"G","....":"H","..":"I",".---":"J","-.-":"K",".-..":"L","--":"M","-.":"N","---":"O",".--.":"P","--.-":"Q",".-.":"R","...":"S","-":"T","..-":"U","...-":"V",".--":"W","-..-":"X","-.--":"Y","--..":"Z","-----":"0",".----":"1","..---":"2","...--":"3","....-":"4",".....":"5","-....":"6","--...":"7","---..":"8","----.":"9",".-.-.-":".","--..--":",","..--..":"?"};
      return s.split(" / ").map(function(word) {
        return word.trim().split(/\s+/).map(function(c) { return map[c] || ""; }).join("");
      }).join(" ");
    }
  },
  nato: {
    name: "NATO Phonetic",
    encode: function(s) {
      var map = {"A":"Alpha","B":"Bravo","C":"Charlie","D":"Delta","E":"Echo","F":"Foxtrot","G":"Golf","H":"Hotel","I":"India","J":"Juliet","K":"Kilo","L":"Lima","M":"Mike","N":"November","O":"Oscar","P":"Papa","Q":"Quebec","R":"Romeo","S":"Sierra","T":"Tango","U":"Uniform","V":"Victor","W":"Whiskey","X":"X-ray","Y":"Yankee","Z":"Zulu","0":"Zero","1":"One","2":"Two","3":"Three","4":"Four","5":"Five","6":"Six","7":"Seven","8":"Eight","9":"Niner"};
      return s.toUpperCase().split("").map(function(c) { return map[c] || c; }).join(" ");
    },
    decode: function(s) {
      var map = {"ALPHA":"A","BRAVO":"B","CHARLIE":"C","DELTA":"D","ECHO":"E","FOXTROT":"F","GOLF":"G","HOTEL":"H","INDIA":"I","JULIET":"J","KILO":"K","LIMA":"L","MIKE":"M","NOVEMBER":"N","OSCAR":"O","PAPA":"P","QUEBEC":"Q","ROMEO":"R","SIERRA":"S","TANGO":"T","UNIFORM":"U","VICTOR":"V","WHISKEY":"W","X-RAY":"X","YANKEE":"Y","ZULU":"Z","ZERO":"0","ONE":"1","TWO":"2","THREE":"3","FOUR":"4","FIVE":"5","SIX":"6","SEVEN":"7","EIGHT":"8","NINER":"9"};
      return s.toUpperCase().split(/\s+/).map(function(w) { return map[w] || w; }).join("");
    }
  },
};

// ── Caesar cipher ──
function caesarEncode(s, shift) {
  var sh = ((Math.trunc(Number(shift) || 0) % 26) + 26) % 26;
  return s.replace(/[a-zA-Z]/g, function(c) {
    var base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + sh) % 26) + base);
  });
}

// ── Vigenere cipher ──
function vigenereEncode(text, key) {
  key = String(key || "").toUpperCase().replace(/[^A-Z]/g, "");
  if (!key) return text;
  var ki = 0;
  return text.replace(/[a-zA-Z]/g, function(c) {
    var base = c <= "Z" ? 65 : 97;
    var shift = key.charCodeAt(ki % key.length) - 65;
    ki++;
    return String.fromCharCode(((c.charCodeAt(0) - base + shift) % 26) + base);
  });
}
function vigenereDecode(text, key) {
  key = String(key || "").toUpperCase().replace(/[^A-Z]/g, "");
  if (!key) return text;
  var ki = 0;
  return text.replace(/[a-zA-Z]/g, function(c) {
    var base = c <= "Z" ? 65 : 97;
    var shift = key.charCodeAt(ki % key.length) - 65;
    ki++;
    return String.fromCharCode(((c.charCodeAt(0) - base - shift + 26) % 26) + base);
  });
}

// ── XOR ──
function xorEncode(text, key) {
  if (!key) return text;
  var out = [];
  for (var i = 0; i < text.length; i++) {
    out.push(String.fromCharCode(text.charCodeAt(i) ^ key.charCodeAt(i % key.length)));
  }
  return out.join("");
}

// ── Hash generators (using SubtleCrypto) ──
async function hashText(text, algo) {
  var data = new TextEncoder().encode(text);
  var hash = await crypto.subtle.digest(algo, data);
  var bytes = new Uint8Array(hash);
  return Array.from(bytes).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("");
}

// ── String analysis ──
function analyzeString(s) {
  var freq = {};
  for (var i = 0; i < s.length; i++) {
    var c = s[i];
    freq[c] = (freq[c] || 0) + 1;
  }
  var entropy = 0;
  var len = s.length;
  if (len > 0) {
    Object.values(freq).forEach(function(count) {
      var p = count / len;
      entropy -= p * Math.log2(p);
    });
  }
  var bytes = new TextEncoder().encode(s).length;
  var upper = (s.match(/[A-Z]/g) || []).length;
  var lower = (s.match(/[a-z]/g) || []).length;
  var digits = (s.match(/[0-9]/g) || []).length;
  var special = s.length - upper - lower - digits;
  return {
    chars: s.length,
    bytes: bytes,
    entropy: entropy,
    upper: upper,
    lower: lower,
    digits: digits,
    special: special,
    uniqueChars: Object.keys(freq).length,
    freq: freq,
  };
}

// ── IP address converter ──
function ipToInt(ip) {
  var parts = ip.split(".");
  if (parts.length !== 4) return NaN;
  return ((parseInt(parts[0]) << 24) | (parseInt(parts[1]) << 16) | (parseInt(parts[2]) << 8) | parseInt(parts[3])) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
function ipToBin(ip) {
  return ip.split(".").map(function(p) { return parseInt(p).toString(2).padStart(8, "0"); }).join(".");
}
function ipToHex(ip) {
  return ip.split(".").map(function(p) { return parseInt(p).toString(16).padStart(2, "0"); }).join("");
}

// ── Timestamp converter ──
function unixToHuman(ts) {
  var d = new Date(ts * 1000);
  return d.toISOString();
}
function humanToUnix(iso) {
  return Math.floor(new Date(iso).getTime() / 1000);
}
function unixToWinFiletime(ts) {
  return BigInt(ts) * 10000000n + 116444736000000000n;
}
function winFiletimeToUnix(ft) {
  return Number((BigInt(ft) - 116444736000000000n) / 10000000n);
}

// ── CSS ──
var ENC_CSS =
  '<style>' +
  '.enc-wrap{font-family:var(--font-body,system-ui);color:var(--txt,#ccc)}' +
  '.enc-input{width:100%;padding:10px;background:var(--card,#161b22);border:1px solid var(--line,#333);color:var(--txt,#ccc);border-radius:4px;font-family:monospace;font-size:.85rem;box-sizing:border-box}' +
  '.enc-input:focus{outline:none;border-color:var(--acc,#00d4ff)}' +
  'textarea.enc-input{min-height:100px;resize:vertical;line-height:1.5}' +
  '.enc-tabs{display:flex;gap:0;border-bottom:1px solid var(--line,#333);margin-bottom:12px;flex-wrap:wrap}' +
  '.enc-tab{padding:7px 14px;cursor:pointer;border:none;background:none;color:var(--mut,#888);font-size:.83rem;border-bottom:2px solid transparent}' +
  '.enc-tab.on{color:var(--acc,#00d4ff);border-bottom-color:var(--acc,#00d4ff)}' +
  '.enc-panel{display:none}.enc-panel.on{display:block}' +
  '.enc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(130px,1fr));gap:6px;margin:10px 0}' +
  '.enc-btn{padding:6px 10px;background:var(--card,#161b22);border:1px solid var(--line,#333);color:var(--txt,#ccc);border-radius:4px;cursor:pointer;font-size:.8rem;text-align:center}' +
  '.enc-btn:hover{border-color:var(--acc,#00d4ff)}' +
  '.enc-btn.on{border-color:var(--acc,#00d4ff);color:var(--acc,#00d4ff);background:rgba(0,212,255,.08)}' +
  '.enc-row{display:flex;gap:12px;align-items:center;margin:8px 0;flex-wrap:wrap}' +
  '.enc-result{padding:10px;background:var(--card,#161b22);border:1px solid var(--line,#333);border-radius:4px;font-family:monospace;font-size:.82rem;max-height:200px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}' +
  '.enc-stat{display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:8px;margin:10px 0}' +
  '.enc-stat-card{padding:10px;background:var(--card,#161b22);border:1px solid var(--line,#333);border-radius:4px;text-align:center}' +
  '.enc-stat-n{font-size:1.4rem;font-weight:700;color:var(--acc,#00d4ff)}' +
  '.enc-stat-l{font-size:.72rem;color:var(--mut,#888)}' +
  '.enc-table{width:100%;border-collapse:collapse;font-size:.82rem}' +
  '.enc-table td{padding:4px 10px;border-bottom:1px solid var(--line,#222);font-family:monospace}' +
  '.enc-table td:first-child{color:var(--mut,#888)}' +
  '.enc-go{padding:8px 18px;background:var(--acc,#00d4ff);color:#000;border:none;border-radius:4px;cursor:pointer;font-weight:600;font-size:.85rem}' +
  '.enc-go:hover{opacity:.85}' +
  '.enc-label{font-size:.82rem;color:var(--mut,#888);margin-bottom:2px;display:block}' +
  '</style>';

// ── Main render ──
export function renderEncodingToolkit(main) {
  var TABS = [
    { id: "convert", label: "Encode / Decode" },
    { id: "cipher", label: "Ciphers" },
    { id: "hash", label: "Hashes" },
    { id: "analyze", label: "String Analysis" },
    { id: "ip", label: "IP Converter" },
    { id: "timestamp", label: "Timestamps" },
    { id: "integer", label: "Integers" },
  ];

  var tabsHtml = TABS.map(function(t) {
    return '<button class="enc-tab' + (t.id === "convert" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  var panelsHtml = TABS.map(function(t) {
    return '<div class="enc-panel' + (t.id === "convert" ? " on" : "") + '" data-panel="' + t.id + '" id="enc-' + t.id + '"></div>';
  }).join("");

  main.innerHTML = ENC_CSS +
    '<div class="enc-wrap">' +
    '<h1 class="pg-h1">Encoding Toolkit</h1>' +
    '<p class="muted pg-sub">Encode, decode, hash, and convert — 20+ formats, all client-side.</p>' +
    '<div class="enc-tabs">' + tabsHtml + '</div>' +
    panelsHtml +
    '</div>';

  main.querySelector(".enc-tabs").onclick = function(e) {
    var btn = e.target.closest(".enc-tab");
    if (!btn) return;
    main.querySelectorAll(".enc-tab").forEach(function(t) { t.classList.toggle("on", t === btn); });
    main.querySelectorAll(".enc-panel").forEach(function(p) { p.classList.toggle("on", p.dataset.panel === btn.dataset.tab); });
  };

  // ── Encode/Decode Panel ──
  var cvtPanel = main.querySelector("#enc-convert");
  var encKeys = Object.keys(ENCODINGS);
  var encBtns = encKeys.map(function(k) {
    return '<button class="enc-btn' + (k === "base64" ? " on" : "") + '" data-enc="' + k + '">' + esc(ENCODINGS[k].name) + '</button>';
  }).join("");

  cvtPanel.innerHTML =
    '<label class="enc-label">Input</label>' +
    '<textarea class="enc-input" id="enc-cvt-in" placeholder="Enter text to encode or decode..."></textarea>' +
    '<div class="enc-grid">' + encBtns + '</div>' +
    '<div class="enc-row">' +
      '<button class="enc-go" id="enc-cvt-enc">Encode</button>' +
      '<button class="enc-go" id="enc-cvt-dec" style="background:var(--card);color:var(--txt);border:1px solid var(--line)">Decode</button>' +
      '<button class="enc-go" id="enc-cvt-swap" style="background:var(--card);color:var(--txt);border:1px solid var(--line);font-size:.78rem">Swap</button>' +
    '</div>' +
    '<label class="enc-label">Output</label>' +
    '<div class="enc-result" id="enc-cvt-out"></div>';

  var curEnc = "base64";
  cvtPanel.querySelector(".enc-grid").onclick = function(e) {
    var btn = e.target.closest(".enc-btn");
    if (!btn) return;
    cvtPanel.querySelectorAll(".enc-btn").forEach(function(b) { b.classList.toggle("on", b === btn); });
    curEnc = btn.dataset.enc;
  };

  cvtPanel.querySelector("#enc-cvt-enc").onclick = function() {
    var input = cvtPanel.querySelector("#enc-cvt-in").value;
    var out = cvtPanel.querySelector("#enc-cvt-out");
    if (!input) { out.textContent = ""; return; }
    try { out.textContent = ENCODINGS[curEnc].encode(input); }
    catch(e) { out.textContent = "[error: " + e.message + "]"; }
  };

  cvtPanel.querySelector("#enc-cvt-dec").onclick = function() {
    var input = cvtPanel.querySelector("#enc-cvt-in").value;
    var out = cvtPanel.querySelector("#enc-cvt-out");
    if (!input) { out.textContent = ""; return; }
    try { out.textContent = ENCODINGS[curEnc].decode(input); }
    catch(e) { out.textContent = "[error: " + e.message + "]"; }
  };

  cvtPanel.querySelector("#enc-cvt-swap").onclick = function() {
    var inp = cvtPanel.querySelector("#enc-cvt-in");
    var out = cvtPanel.querySelector("#enc-cvt-out");
    inp.value = out.textContent;
    out.textContent = "";
  };

  // ── Cipher Panel ──
  var cipherPanel = main.querySelector("#enc-cipher");
  cipherPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Classical Ciphers</h3>' +
    '<label class="enc-label">Input</label>' +
    '<textarea class="enc-input" id="enc-cip-in" placeholder="Enter text..."></textarea>' +
    '<div class="enc-row">' +
      '<div><label class="enc-label">Cipher</label><select class="enc-input" id="enc-cip-type" style="width:auto">' +
        '<option value="caesar">Caesar</option>' +
        '<option value="vigenere">Vigenere</option>' +
        '<option value="xor">XOR</option>' +
      '</select></div>' +
      '<div id="enc-cip-key-area"><label class="enc-label">Shift (1-25)</label><input class="enc-input" id="enc-cip-shift" type="number" min="1" max="25" value="13" style="width:80px"></div>' +
    '</div>' +
    '<div class="enc-row">' +
      '<button class="enc-go" id="enc-cip-enc">Encode</button>' +
      '<button class="enc-go" id="enc-cip-dec" style="background:var(--card);color:var(--txt);border:1px solid var(--line)">Decode</button>' +
      '<button class="enc-go" id="enc-cip-brute" style="background:var(--card);color:var(--txt);border:1px solid var(--line);font-size:.78rem">Brute Force (Caesar)</button>' +
    '</div>' +
    '<label class="enc-label">Output</label>' +
    '<div class="enc-result" id="enc-cip-out"></div>';

  var cipType = cipherPanel.querySelector("#enc-cip-type");
  cipType.onchange = function() {
    var area = cipherPanel.querySelector("#enc-cip-key-area");
    if (cipType.value === "caesar") {
      area.innerHTML = '<label class="enc-label">Shift (1-25)</label><input class="enc-input" id="enc-cip-shift" type="number" min="1" max="25" value="13" style="width:80px">';
    } else {
      area.innerHTML = '<label class="enc-label">Key</label><input class="enc-input" id="enc-cip-key" placeholder="Encryption key..." style="width:200px">';
    }
  };

  cipherPanel.querySelector("#enc-cip-enc").onclick = function() {
    var text = cipherPanel.querySelector("#enc-cip-in").value;
    var out = cipherPanel.querySelector("#enc-cip-out");
    if (cipType.value === "caesar") {
      var shift = parseInt((cipherPanel.querySelector("#enc-cip-shift") || {}).value) || 13;
      out.textContent = caesarEncode(text, shift);
    } else if (cipType.value === "vigenere") {
      var key = (cipherPanel.querySelector("#enc-cip-key") || {}).value || "";
      out.textContent = vigenereEncode(text, key);
    } else {
      var key2 = (cipherPanel.querySelector("#enc-cip-key") || {}).value || "";
      out.textContent = ENCODINGS.hex.encode(xorEncode(text, key2));
    }
  };

  cipherPanel.querySelector("#enc-cip-dec").onclick = function() {
    var text = cipherPanel.querySelector("#enc-cip-in").value;
    var out = cipherPanel.querySelector("#enc-cip-out");
    if (cipType.value === "caesar") {
      var shift = parseInt((cipherPanel.querySelector("#enc-cip-shift") || {}).value) || 13;
      out.textContent = caesarEncode(text, 26 - shift);
    } else if (cipType.value === "vigenere") {
      var key = (cipherPanel.querySelector("#enc-cip-key") || {}).value || "";
      out.textContent = vigenereDecode(text, key);
    } else {
      var key2 = (cipherPanel.querySelector("#enc-cip-key") || {}).value || "";
      var decoded = ENCODINGS.hex.decode(text);
      out.textContent = xorEncode(decoded, key2);
    }
  };

  cipherPanel.querySelector("#enc-cip-brute").onclick = function() {
    var text = cipherPanel.querySelector("#enc-cip-in").value;
    var out = cipherPanel.querySelector("#enc-cip-out");
    var lines = [];
    for (var shift = 1; shift <= 25; shift++) {
      lines.push("ROT-" + shift.toString().padStart(2, " ") + ": " + caesarEncode(text, shift));
    }
    out.textContent = lines.join("\n");
  };

  // ── Hash Panel ──
  var hashPanel = main.querySelector("#enc-hash");
  hashPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Hash Generators</h3>' +
    '<label class="enc-label">Input</label>' +
    '<textarea class="enc-input" id="enc-hash-in" placeholder="Enter text to hash..."></textarea>' +
    '<div class="enc-row">' +
      '<button class="enc-go" id="enc-hash-go">Generate All Hashes</button>' +
      '<div><label class="enc-label">HMAC Key (optional)</label><input class="enc-input" id="enc-hmac-key" placeholder="Key for HMAC" style="width:200px"></div>' +
    '</div>' +
    '<table class="enc-table" id="enc-hash-out"><tr><td colspan="2" class="muted">Enter text and click Generate</td></tr></table>';

  hashPanel.querySelector("#enc-hash-go").onclick = async function() {
    var text = hashPanel.querySelector("#enc-hash-in").value;
    var table = hashPanel.querySelector("#enc-hash-out");
    if (!text) { table.innerHTML = '<tr><td class="muted">Enter text first</td></tr>'; return; }

    table.innerHTML = '<tr><td class="muted">Generating...</td></tr>';
    var results = [];
    try {
      var algos = [
        ["SHA-1", "SHA-1"],
        ["SHA-256", "SHA-256"],
        ["SHA-384", "SHA-384"],
        ["SHA-512", "SHA-512"],
      ];
      for (var i = 0; i < algos.length; i++) {
        var h = await hashText(text, algos[i][1]);
        results.push([algos[i][0], h]);
      }

      // HMAC
      var hmacKey = hashPanel.querySelector("#enc-hmac-key").value;
      if (hmacKey) {
        var keyData = new TextEncoder().encode(hmacKey);
        var cryptoKey = await crypto.subtle.importKey("raw", keyData, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
        var sig = await crypto.subtle.sign("HMAC", cryptoKey, new TextEncoder().encode(text));
        results.push(["HMAC-SHA256", Array.from(new Uint8Array(sig)).map(function(b) { return b.toString(16).padStart(2, "0"); }).join("")]);
      }
    } catch(e) {
      results.push(["Error", e.message]);
    }

    table.innerHTML = results.map(function(r) {
      return '<tr><td style="width:120px">' + esc(r[0]) + '</td><td style="word-break:break-all">' + esc(r[1]) + '</td></tr>';
    }).join("");
  };

  // ── String Analysis Panel ──
  var analyzePanel = main.querySelector("#enc-analyze");
  analyzePanel.innerHTML =
    '<h3 style="margin:0 0 10px">String Analysis</h3>' +
    '<label class="enc-label">Input</label>' +
    '<textarea class="enc-input" id="enc-ana-in" placeholder="Paste text to analyze..."></textarea>' +
    '<button class="enc-go" id="enc-ana-go" style="margin:8px 0">Analyze</button>' +
    '<div id="enc-ana-out"></div>';

  analyzePanel.querySelector("#enc-ana-go").onclick = function() {
    var text = analyzePanel.querySelector("#enc-ana-in").value;
    var out = analyzePanel.querySelector("#enc-ana-out");
    if (!text) { out.innerHTML = '<p class="muted">Enter text to analyze.</p>'; return; }

    var stats = analyzeString(text);
    var html =
      '<div class="enc-stat">' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.chars + '</div><div class="enc-stat-l">Characters</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.bytes + '</div><div class="enc-stat-l">Bytes (UTF-8)</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.entropy.toFixed(2) + '</div><div class="enc-stat-l">Entropy (bits/char)</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.uniqueChars + '</div><div class="enc-stat-l">Unique Chars</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.upper + '</div><div class="enc-stat-l">Uppercase</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.lower + '</div><div class="enc-stat-l">Lowercase</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.digits + '</div><div class="enc-stat-l">Digits</div></div>' +
        '<div class="enc-stat-card"><div class="enc-stat-n">' + stats.special + '</div><div class="enc-stat-l">Special</div></div>' +
      '</div>';

    // Frequency table (top 20)
    var sorted = Object.entries(stats.freq).sort(function(a, b) { return b[1] - a[1]; }).slice(0, 20);
    html += '<h4 style="margin:12px 0 6px;font-size:.85rem">Character Frequency (top 20)</h4>';
    html += '<table class="enc-table">';
    for (var i = 0; i < sorted.length; i++) {
      var ch = sorted[i][0];
      var count = sorted[i][1];
      var pct = (count / stats.chars * 100).toFixed(1);
      var display = ch === " " ? "SPACE" : ch === "\n" ? "LF" : ch === "\t" ? "TAB" : ch === "\r" ? "CR" : ch;
      html += '<tr><td>' + esc(display) + '</td><td>' + count + '</td><td>' + pct + '%</td></tr>';
    }
    html += '</table>';
    out.innerHTML = html;
  };

  // ── IP Converter Panel ──
  var ipPanel = main.querySelector("#enc-ip");
  ipPanel.innerHTML =
    '<h3 style="margin:0 0 10px">IP Address Converter</h3>' +
    '<label class="enc-label">IPv4 Address</label>' +
    '<input class="enc-input" id="enc-ip-in" placeholder="e.g. 192.168.1.1">' +
    '<button class="enc-go" id="enc-ip-go" style="margin:8px 0">Convert</button>' +
    '<table class="enc-table" id="enc-ip-out"><tr><td class="muted">Enter an IP address</td></tr></table>';

  ipPanel.querySelector("#enc-ip-go").onclick = function() {
    var ip = ipPanel.querySelector("#enc-ip-in").value.trim();
    var out = ipPanel.querySelector("#enc-ip-out");
    var intVal = ipToInt(ip);
    if (isNaN(intVal)) { out.innerHTML = '<tr><td style="color:#f44">Invalid IPv4 address</td></tr>'; return; }
    out.innerHTML =
      '<tr><td>Dotted Decimal</td><td>' + esc(ip) + '</td></tr>' +
      '<tr><td>Integer</td><td>' + intVal + '</td></tr>' +
      '<tr><td>Hex</td><td>0x' + ipToHex(ip).toUpperCase() + '</td></tr>' +
      '<tr><td>Binary</td><td>' + ipToBin(ip) + '</td></tr>' +
      '<tr><td>Reversed (PTR)</td><td>' + ip.split(".").reverse().join(".") + '.in-addr.arpa</td></tr>' +
      '<tr><td>Class</td><td>' + (function() {
        var first = parseInt(ip.split(".")[0]);
        if (first < 128) return "A (1.0.0.0 – 126.255.255.255)";
        if (first < 192) return "B (128.0.0.0 – 191.255.255.255)";
        if (first < 224) return "C (192.0.0.0 – 223.255.255.255)";
        if (first < 240) return "D Multicast (224.0.0.0 – 239.255.255.255)";
        return "E Reserved (240.0.0.0 – 255.255.255.255)";
      })() + '</td></tr>' +
      '<tr><td>Private?</td><td>' + (function() {
        var parts = ip.split(".").map(Number);
        if (parts[0] === 10) return "Yes (10.0.0.0/8)";
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return "Yes (172.16.0.0/12)";
        if (parts[0] === 192 && parts[1] === 168) return "Yes (192.168.0.0/16)";
        if (parts[0] === 127) return "Loopback (127.0.0.0/8)";
        return "No (public)";
      })() + '</td></tr>';
  };

  // ── Timestamp Panel ──
  var tsPanel = main.querySelector("#enc-timestamp");
  tsPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Timestamp Converter</h3>' +
    '<div class="enc-row">' +
      '<div style="flex:1"><label class="enc-label">Unix Epoch</label><input class="enc-input" id="enc-ts-unix" placeholder="e.g. 1694534400"></div>' +
      '<div style="flex:1"><label class="enc-label">ISO 8601</label><input class="enc-input" id="enc-ts-iso" placeholder="e.g. 2024-01-15T12:00:00Z"></div>' +
    '</div>' +
    '<div class="enc-row">' +
      '<button class="enc-go" id="enc-ts-now" style="font-size:.78rem;background:var(--card);color:var(--txt);border:1px solid var(--line)">Now</button>' +
      '<button class="enc-go" id="enc-ts-from-unix">Unix to All</button>' +
      '<button class="enc-go" id="enc-ts-from-iso" style="background:var(--card);color:var(--txt);border:1px solid var(--line)">ISO to All</button>' +
    '</div>' +
    '<table class="enc-table" id="enc-ts-out"><tr><td class="muted">Enter a timestamp</td></tr></table>';

  tsPanel.querySelector("#enc-ts-now").onclick = function() {
    var now = Math.floor(Date.now() / 1000);
    tsPanel.querySelector("#enc-ts-unix").value = now;
    tsPanel.querySelector("#enc-ts-iso").value = new Date().toISOString();
    convertTs(now);
  };

  tsPanel.querySelector("#enc-ts-from-unix").onclick = function() {
    var ts = parseInt(tsPanel.querySelector("#enc-ts-unix").value);
    if (isNaN(ts)) return;
    tsPanel.querySelector("#enc-ts-iso").value = new Date(ts * 1000).toISOString();
    convertTs(ts);
  };

  tsPanel.querySelector("#enc-ts-from-iso").onclick = function() {
    var iso = tsPanel.querySelector("#enc-ts-iso").value;
    var ts = humanToUnix(iso);
    if (isNaN(ts)) return;
    tsPanel.querySelector("#enc-ts-unix").value = ts;
    convertTs(ts);
  };

  function convertTs(ts) {
    var d = new Date(ts * 1000);
    var out = tsPanel.querySelector("#enc-ts-out");
    var ft;
    try { ft = unixToWinFiletime(ts).toString(); } catch(e) { ft = "N/A"; }
    out.innerHTML =
      '<tr><td>Unix Epoch</td><td>' + ts + '</td></tr>' +
      '<tr><td>ISO 8601</td><td>' + d.toISOString() + '</td></tr>' +
      '<tr><td>UTC</td><td>' + d.toUTCString() + '</td></tr>' +
      '<tr><td>Local</td><td>' + d.toString() + '</td></tr>' +
      '<tr><td>Milliseconds</td><td>' + (ts * 1000) + '</td></tr>' +
      '<tr><td>Windows FILETIME</td><td>' + ft + '</td></tr>' +
      '<tr><td>Day of Week</td><td>' + ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"][d.getDay()] + '</td></tr>' +
      '<tr><td>Day of Year</td><td>' + (Math.round((new Date(d.getFullYear(), d.getMonth(), d.getDate()) - new Date(d.getFullYear(), 0, 1)) / 86400000) + 1) + '</td></tr>';
  }

  // ── Integer Converter Panel ──
  var intPanel = main.querySelector("#enc-integer");
  intPanel.innerHTML =
    '<h3 style="margin:0 0 10px">Integer Converter</h3>' +
    '<label class="enc-label">Input</label>' +
    '<div class="enc-row">' +
      '<input class="enc-input" id="enc-int-in" placeholder="e.g. 255 or 0xFF or 0b11111111" style="flex:1">' +
      '<button class="enc-go" id="enc-int-go">Convert</button>' +
    '</div>' +
    '<table class="enc-table" id="enc-int-out"><tr><td class="muted">Enter a number</td></tr></table>';

  intPanel.querySelector("#enc-int-go").onclick = function() {
    var raw = intPanel.querySelector("#enc-int-in").value.trim();
    var out = intPanel.querySelector("#enc-int-out");
    var n;
    if (raw.startsWith("0x") || raw.startsWith("0X")) n = parseInt(raw, 16);
    else if (raw.startsWith("0b") || raw.startsWith("0B")) n = parseInt(raw.substring(2), 2);
    else if (raw.startsWith("0o") || raw.startsWith("0O")) n = parseInt(raw.substring(2), 8);
    else n = parseInt(raw, 10);

    if (isNaN(n)) { out.innerHTML = '<tr><td style="color:#f44">Invalid number</td></tr>'; return; }

    out.innerHTML =
      '<tr><td>Decimal</td><td>' + n + '</td></tr>' +
      '<tr><td>Hex</td><td>0x' + (n >>> 0).toString(16).toUpperCase() + '</td></tr>' +
      '<tr><td>Octal</td><td>0o' + (n >>> 0).toString(8) + '</td></tr>' +
      '<tr><td>Binary (32-bit)</td><td>0b' + (n >>> 0).toString(2).padStart(32, "0") + '</td></tr>' +
      '<tr><td>Binary (16-bit)</td><td>0b' + (n & 0xFFFF).toString(2).padStart(16, "0") + '</td></tr>' +
      '<tr><td>Binary (8-bit)</td><td>0b' + (n & 0xFF).toString(2).padStart(8, "0") + '</td></tr>' +
      '<tr><td>Signed 32-bit</td><td>' + (n | 0) + '</td></tr>' +
      '<tr><td>Unsigned 32-bit</td><td>' + (n >>> 0) + '</td></tr>' +
      '<tr><td>ASCII</td><td>' + (n >= 32 && n < 127 ? "'" + String.fromCharCode(n) + "'" : n === 10 ? "LF" : n === 13 ? "CR" : n === 9 ? "TAB" : n === 0 ? "NULL" : "non-printable") + '</td></tr>' +
      '<tr><td>Big-endian bytes</td><td>' + [(n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF].map(function(b) { return b.toString(16).padStart(2, "0"); }).join(" ") + '</td></tr>' +
      '<tr><td>Little-endian bytes</td><td>' + [n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF, (n >> 24) & 0xFF].map(function(b) { return b.toString(16).padStart(2, "0"); }).join(" ") + '</td></tr>';
  };
}
