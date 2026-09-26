// Steganography Tool — hide and extract data in images, all client-side.
// Copyright (c) 2026 Darknode-Official. All rights reserved.

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ── UTF-8 <-> binary string ──
// A "binary string" holds one byte (0-255) per char. Messages and passwords
// are converted to their UTF-8 byte sequence first so that non-ASCII text
// (accents, CJK, emoji) survives hiding/extraction instead of being truncated
// to its low byte.
function utf8Encode(str) { return unescape(encodeURIComponent(str)); }
function utf8Decode(bin) { try { return decodeURIComponent(escape(bin)); } catch (e) { return bin; } }

// ── XOR encryption (byte-wise over UTF-8 bytes) ──
function xorEncrypt(text, password) {
  if (!password) return text;
  var pw = utf8Encode(password);
  var result = [];
  for (var i = 0; i < text.length; i++) {
    result.push(String.fromCharCode(text.charCodeAt(i) ^ pw.charCodeAt(i % pw.length)));
  }
  return result.join("");
}

// ── Text ↔ binary ──
function textToBits(text) {
  var bits = [];
  for (var i = 0; i < text.length; i++) {
    var code = text.charCodeAt(i);
    for (var b = 7; b >= 0; b--) {
      bits.push((code >> b) & 1);
    }
  }
  return bits;
}

function bitsToText(bits) {
  var chars = [];
  for (var i = 0; i + 7 < bits.length; i += 8) {
    var byte = 0;
    for (var b = 0; b < 8; b++) {
      byte = (byte << 1) | bits[i + b];
    }
    // Do NOT stop at a zero byte: callers slice to the exact message length
    // from the header, and XOR-encrypted payloads legitimately contain 0x00.
    chars.push(String.fromCharCode(byte));
  }
  return chars.join("");
}

// ── LSB Encoding (1-bit and 2-bit) ──
function lsbEncode(imageData, message, bitsPerChannel, password) {
  var encrypted = xorEncrypt(utf8Encode(message), password);
  // Prepend 32-bit length header
  var len = encrypted.length;
  var headerBits = [];
  for (var i = 31; i >= 0; i--) {
    headerBits.push((len >> i) & 1);
  }
  var msgBits = textToBits(encrypted);
  var allBits = headerBits.concat(msgBits);

  var data = imageData.data;
  var capacity = Math.floor((data.length / 4) * 3 * bitsPerChannel);
  if (allBits.length > capacity) {
    return { success: false, error: "Message too large. Need " + allBits.length + " bits, image holds " + capacity + " bits (" + Math.floor(capacity / 8) + " bytes)." };
  }

  var bitIdx = 0;
  var mask = bitsPerChannel === 1 ? 0xFE : 0xFC;

  for (var px = 0; px < data.length && bitIdx < allBits.length; px += 4) {
    for (var ch = 0; ch < 3 && bitIdx < allBits.length; ch++) {
      if (bitsPerChannel === 1) {
        data[px + ch] = (data[px + ch] & mask) | allBits[bitIdx];
        bitIdx++;
      } else {
        var val = 0;
        val |= (bitIdx < allBits.length ? allBits[bitIdx] : 0) << 1;
        bitIdx++;
        val |= (bitIdx < allBits.length ? allBits[bitIdx] : 0);
        bitIdx++;
        data[px + ch] = (data[px + ch] & mask) | val;
      }
    }
  }
  return { success: true, bitsUsed: allBits.length, capacity: capacity };
}

// ── LSB Decoding ──
function lsbDecode(imageData, bitsPerChannel, password) {
  var data = imageData.data;
  var bits = [];
  var mask = bitsPerChannel === 1 ? 1 : 3;

  for (var px = 0; px < data.length; px += 4) {
    for (var ch = 0; ch < 3; ch++) {
      var val = data[px + ch] & mask;
      if (bitsPerChannel === 1) {
        bits.push(val);
      } else {
        bits.push((val >> 1) & 1);
        bits.push(val & 1);
      }
    }
  }

  // Read 32-bit length header
  if (bits.length < 32) return { success: false, error: "Image too small to contain data." };
  var len = 0;
  for (var i = 0; i < 32; i++) {
    len = (len << 1) | bits[i];
  }
  if (len <= 0 || len > 10000000) {
    return { success: false, error: "No hidden message detected (invalid length header: " + len + ")." };
  }
  var neededBits = 32 + len * 8;
  if (neededBits > bits.length) {
    return { success: false, error: "Corrupted data — expected " + len + " chars but not enough bits." };
  }

  var msgBits = bits.slice(32, neededBits);
  var decrypted = bitsToText(msgBits);
  if (password) {
    decrypted = xorEncrypt(decrypted, password);
  }
  return { success: true, message: utf8Decode(decrypted), length: len };
}

// ── Spread Spectrum Encoding ──
function spreadEncode(imageData, message, password, spread) {
  spread = spread || 7;
  var encrypted = xorEncrypt(utf8Encode(message), password);
  var len = encrypted.length;
  var headerBits = [];
  for (var i = 31; i >= 0; i--) headerBits.push((len >> i) & 1);
  var msgBits = headerBits.concat(textToBits(encrypted));

  var data = imageData.data;
  var totalChannels = (data.length / 4) * 3;
  var capacity = Math.floor(totalChannels / spread);
  if (msgBits.length > capacity) {
    return { success: false, error: "Message too large for spread spectrum. Need " + msgBits.length + " channels at spread=" + spread + ", image has " + totalChannels + " channels." };
  }

  var chIdx = 0;
  for (var b = 0; b < msgBits.length; b++) {
    var px = Math.floor(chIdx / 3);
    var ch = chIdx % 3;
    var pxOff = px * 4;
    if (pxOff + ch >= data.length) break;
    data[pxOff + ch] = (data[pxOff + ch] & 0xFE) | msgBits[b];
    chIdx += spread;
  }
  return { success: true, bitsUsed: msgBits.length, capacity: capacity };
}

function spreadDecode(imageData, password, spread) {
  spread = spread || 7;
  var data = imageData.data;
  var bits = [];
  var totalChannels = (data.length / 4) * 3;
  var maxBits = Math.floor(totalChannels / spread);

  var chIdx = 0;
  for (var b = 0; b < maxBits && chIdx < totalChannels; b++) {
    var px = Math.floor(chIdx / 3);
    var ch = chIdx % 3;
    var pxOff = px * 4;
    if (pxOff + ch >= data.length) break;
    bits.push(data[pxOff + ch] & 1);
    chIdx += spread;
  }

  if (bits.length < 32) return { success: false, error: "Not enough data for spread spectrum decode." };
  var len = 0;
  for (var i = 0; i < 32; i++) len = (len << 1) | bits[i];
  if (len <= 0 || len > 10000000) return { success: false, error: "No hidden message detected." };
  var neededBits = 32 + len * 8;
  if (neededBits > bits.length) return { success: false, error: "Corrupted spread spectrum data." };

  var msgBits = bits.slice(32, neededBits);
  var decrypted = bitsToText(msgBits);
  if (password) decrypted = xorEncrypt(decrypted, password);
  return { success: true, message: utf8Decode(decrypted), length: len };
}

// ── Bit plane extraction ──
function extractBitPlane(imageData, channel, bit) {
  var w = imageData.width, h = imageData.height;
  var canvas = document.createElement("canvas");
  canvas.width = w; canvas.height = h;
  var ctx = canvas.getContext("2d");
  var out = ctx.createImageData(w, h);
  var src = imageData.data, dst = out.data;

  for (var i = 0; i < src.length; i += 4) {
    var val = ((src[i + channel] >> bit) & 1) * 255;
    dst[i] = val;
    dst[i + 1] = val;
    dst[i + 2] = val;
    dst[i + 3] = 255;
  }
  ctx.putImageData(out, 0, 0);
  return canvas;
}

// ── Chi-square analysis ──
function chiSquareAnalysis(imageData, channel) {
  var data = imageData.data;
  var pairs = new Array(128).fill(0);
  for (var i = 0; i < data.length; i += 4) {
    var v = data[i + channel];
    pairs[Math.floor(v / 2)]++;
  }
  var totalPixels = data.length / 4;
  var expected = totalPixels / 128;
  var chiSq = 0;
  for (var j = 0; j < 128; j++) {
    var diff = pairs[j] - expected;
    chiSq += (diff * diff) / expected;
  }
  var df = 127;
  var pValue = chiSq > df * 2 ? 0.0 : chiSq < df * 0.5 ? 1.0 : 1.0 - (chiSq - df) / df;
  return { chiSquare: chiSq, degreesOfFreedom: df, pValue: Math.max(0, Math.min(1, pValue)), suspicious: pValue < 0.05 };
}

// ── Histogram ──
function computeHistogram(imageData) {
  var r = new Array(256).fill(0);
  var g = new Array(256).fill(0);
  var b = new Array(256).fill(0);
  var data = imageData.data;
  for (var i = 0; i < data.length; i += 4) {
    r[data[i]]++;
    g[data[i + 1]]++;
    b[data[i + 2]]++;
  }
  return { r: r, g: g, b: b };
}

function drawHistogram(canvas, histogram, label) {
  var ctx = canvas.getContext("2d");
  var w = canvas.width, h = canvas.height;
  ctx.fillStyle = "#0d1117";
  ctx.fillRect(0, 0, w, h);

  var channels = [
    { data: histogram.r, color: "rgba(255,80,80,0.7)" },
    { data: histogram.g, color: "rgba(80,255,80,0.7)" },
    { data: histogram.b, color: "rgba(80,80,255,0.7)" }
  ];

  var maxVal = 0;
  for (var c = 0; c < 3; c++) {
    for (var i = 0; i < 256; i++) {
      if (channels[c].data[i] > maxVal) maxVal = channels[c].data[i];
    }
  }
  if (maxVal === 0) return;

  var barW = w / 256;
  var drawH = h - 20;
  for (var c2 = 0; c2 < 3; c2++) {
    ctx.fillStyle = channels[c2].color;
    for (var j = 0; j < 256; j++) {
      var barH = (channels[c2].data[j] / maxVal) * drawH;
      ctx.fillRect(j * barW, drawH - barH, Math.max(barW - 0.5, 1), barH);
    }
  }

  ctx.fillStyle = "#888";
  ctx.font = "11px monospace";
  ctx.fillText(label || "", 4, h - 4);
  ctx.fillText("0", 4, drawH - 2);
  ctx.fillText("255", w - 28, drawH - 2);
}

// ── Entropy calculation ──
function calculateEntropy(data, start, length) {
  var freq = new Array(256).fill(0);
  var end = Math.min(start + length, data.length);
  var total = 0;
  for (var i = start; i < end; i++) {
    freq[data[i]]++;
    total++;
  }
  if (total === 0) return 0;
  var entropy = 0;
  for (var j = 0; j < 256; j++) {
    if (freq[j] > 0) {
      var p = freq[j] / total;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

// ── File signature detection ──
var FILE_SIGNATURES = [
  { name: "JPEG", magic: [0xFF, 0xD8, 0xFF], eof: [0xFF, 0xD9] },
  { name: "PNG", magic: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], eof: null },
  { name: "GIF87a", magic: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], eof: [0x3B] },
  { name: "GIF89a", magic: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], eof: [0x3B] },
  { name: "BMP", magic: [0x42, 0x4D], eof: null },
  { name: "TIFF (LE)", magic: [0x49, 0x49, 0x2A, 0x00], eof: null },
  { name: "TIFF (BE)", magic: [0x4D, 0x4D, 0x00, 0x2A], eof: null },
  { name: "WEBP", magic: [0x52, 0x49, 0x46, 0x46], eof: null },
  { name: "PSD", magic: [0x38, 0x42, 0x50, 0x53], eof: null },
  { name: "PDF", magic: [0x25, 0x50, 0x44, 0x46], eof: null },
  { name: "ZIP/DOCX/XLSX", magic: [0x50, 0x4B, 0x03, 0x04], eof: null },
  { name: "RAR", magic: [0x52, 0x61, 0x72, 0x21], eof: null },
  { name: "7z", magic: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], eof: null },
  { name: "PE/EXE", magic: [0x4D, 0x5A], eof: null },
  { name: "ELF", magic: [0x7F, 0x45, 0x4C, 0x46], eof: null },
];

function detectFileType(bytes) {
  for (var i = 0; i < FILE_SIGNATURES.length; i++) {
    var sig = FILE_SIGNATURES[i];
    var match = true;
    for (var j = 0; j < sig.magic.length && j < bytes.length; j++) {
      if (bytes[j] !== sig.magic[j]) { match = false; break; }
    }
    if (match) return sig;
  }
  return null;
}

function findAppendedData(bytes) {
  // Check for data after JPEG EOF marker (FF D9)
  for (var i = bytes.length - 1; i >= 2; i--) {
    if (bytes[i - 1] === 0xFF && bytes[i] === 0xD9) {
      if (i < bytes.length - 1) {
        return { offset: i + 1, size: bytes.length - i - 1 };
      }
      return null;
    }
  }
  return null;
}

// ── EXIF-like metadata reader ──
function readImageMetadata(bytes) {
  var meta = [];
  var sig = detectFileType(bytes);
  meta.push({ key: "File Type", value: sig ? sig.name : "Unknown" });
  meta.push({ key: "File Size", value: bytes.length.toLocaleString() + " bytes (" + (bytes.length / 1024).toFixed(1) + " KB)" });

  // JPEG EXIF
  if (bytes[0] === 0xFF && bytes[1] === 0xD8) {
    var offset = 2;
    while (offset < bytes.length - 4) {
      if (bytes[offset] !== 0xFF) break;
      var marker = bytes[offset + 1];
      if (marker === 0xDA) break; // Start of scan
      var segLen = (bytes[offset + 2] << 8) | bytes[offset + 3];

      if (marker === 0xE1) { // APP1 / EXIF
        var exifStr = "";
        for (var e = offset + 4; e < offset + 4 + 4 && e < bytes.length; e++) {
          exifStr += String.fromCharCode(bytes[e]);
        }
        if (exifStr === "Exif") {
          meta.push({ key: "EXIF Data", value: "Present (APP1 segment, " + segLen + " bytes)" });
          // Parse TIFF header inside EXIF
          var tiffStart = offset + 10;
          if (tiffStart + 8 < bytes.length) {
            var byteOrder = (bytes[tiffStart] === 0x49) ? "Little Endian" : "Big Endian";
            meta.push({ key: "Byte Order", value: byteOrder });
          }
        }
      } else if (marker === 0xE0) { // APP0 / JFIF
        meta.push({ key: "JFIF Segment", value: segLen + " bytes" });
        if (offset + 11 < bytes.length) {
          var major = bytes[offset + 9];
          var minor = bytes[offset + 10];
          meta.push({ key: "JFIF Version", value: major + "." + minor });
        }
      } else if (marker === 0xFE) { // Comment
        var comment = "";
        for (var cm = offset + 4; cm < offset + 2 + segLen && cm < bytes.length; cm++) {
          var cc = bytes[cm];
          if (cc >= 32 && cc < 127) comment += String.fromCharCode(cc);
        }
        if (comment) meta.push({ key: "Comment", value: comment });
      } else if (marker === 0xC0 || marker === 0xC2) { // SOF
        if (offset + 9 < bytes.length) {
          var precision = bytes[offset + 4];
          var height = (bytes[offset + 5] << 8) | bytes[offset + 6];
          var width = (bytes[offset + 7] << 8) | bytes[offset + 8];
          var components = bytes[offset + 9];
          meta.push({ key: "Dimensions", value: width + " x " + height });
          meta.push({ key: "Color Depth", value: (precision * components) + " bits (" + components + " components)" });
          meta.push({ key: "Compression", value: marker === 0xC0 ? "Baseline DCT" : "Progressive DCT" });
        }
      }
      offset += 2 + segLen;
    }
  }

  // PNG chunks
  if (bytes[0] === 0x89 && bytes[1] === 0x50) {
    var pos = 8;
    while (pos + 12 < bytes.length) {
      var chunkLen = (bytes[pos] << 24) | (bytes[pos + 1] << 16) | (bytes[pos + 2] << 8) | bytes[pos + 3];
      var chunkType = "";
      for (var ct = 0; ct < 4; ct++) chunkType += String.fromCharCode(bytes[pos + 4 + ct]);

      if (chunkType === "IHDR" && pos + 20 < bytes.length) {
        var w = (bytes[pos + 8] << 24) | (bytes[pos + 9] << 16) | (bytes[pos + 10] << 8) | bytes[pos + 11];
        var h2 = (bytes[pos + 12] << 24) | (bytes[pos + 13] << 16) | (bytes[pos + 14] << 8) | bytes[pos + 15];
        var bitDepth = bytes[pos + 16];
        var colorType = bytes[pos + 17];
        var colorNames = { 0: "Grayscale", 2: "RGB", 3: "Indexed", 4: "Grayscale+Alpha", 6: "RGBA" };
        meta.push({ key: "Dimensions", value: w + " x " + h2 });
        meta.push({ key: "Bit Depth", value: bitDepth.toString() });
        meta.push({ key: "Color Type", value: (colorNames[colorType] || "Unknown") + " (" + colorType + ")" });
        meta.push({ key: "Interlace", value: bytes[pos + 20] ? "Adam7" : "None" });
      } else if (chunkType === "tEXt" || chunkType === "iTXt") {
        var txt = "";
        for (var ti = pos + 8; ti < pos + 8 + chunkLen && ti < bytes.length; ti++) {
          var tc = bytes[ti];
          txt += (tc >= 32 && tc < 127) ? String.fromCharCode(tc) : (tc === 0 ? ": " : ".");
        }
        if (txt.length < 200) meta.push({ key: "Text Chunk (" + chunkType + ")", value: txt });
      } else if (chunkType === "pHYs" && pos + 20 < bytes.length) {
        var ppuX = (bytes[pos + 8] << 24) | (bytes[pos + 9] << 16) | (bytes[pos + 10] << 8) | bytes[pos + 11];
        var ppuY = (bytes[pos + 12] << 24) | (bytes[pos + 13] << 16) | (bytes[pos + 14] << 8) | bytes[pos + 15];
        var unit = bytes[pos + 16];
        meta.push({ key: "Pixel Density", value: ppuX + " x " + ppuY + (unit === 1 ? " pixels/meter" : " (unknown unit)") });
      } else if (chunkType === "tIME" && pos + 15 < bytes.length) {
        var yr = (bytes[pos + 8] << 8) | bytes[pos + 9];
        meta.push({ key: "Last Modified", value: yr + "-" + bytes[pos + 10] + "-" + bytes[pos + 11] + " " + bytes[pos + 12] + ":" + bytes[pos + 13] + ":" + bytes[pos + 14] });
      }

      if (chunkType === "IEND") break;
      pos += 12 + chunkLen;
    }
  }

  // Entropy
  var ent = calculateEntropy(bytes, 0, bytes.length);
  meta.push({ key: "File Entropy", value: ent.toFixed(4) + " bits/byte" + (ent > 7.5 ? " (high — possibly encrypted/compressed)" : ent > 6.0 ? " (moderate)" : " (low — may contain patterns)") });

  // Appended data check
  var appended = findAppendedData(bytes);
  if (appended) {
    meta.push({ key: "Appended Data", value: "DETECTED — " + appended.size + " bytes after EOF at offset 0x" + appended.offset.toString(16).toUpperCase() });
  }

  return meta;
}

// ── Capacity calculator ──
function calcCapacity(width, height, bitsPerChannel, mode) {
  var totalPixels = width * height;
  var totalChannels = totalPixels * 3; // RGB
  var headerBits = 32;
  var capacityBits;

  if (mode === "spread") {
    capacityBits = Math.floor(totalChannels / 7) - headerBits;
  } else {
    capacityBits = totalChannels * bitsPerChannel - headerBits;
  }
  return {
    bits: capacityBits,
    bytes: Math.floor(capacityBits / 8),
    chars: Math.floor(capacityBits / 8),
    kb: (Math.floor(capacityBits / 8) / 1024).toFixed(2)
  };
}

// ── CSS ──
var STEG_CSS = [
  '<style>',
  '.steg-wrap { font-family: var(--font-body, system-ui); color: var(--txt, #ccc); }',
  '.steg-tabs { display: flex; gap: 0; border-bottom: 1px solid var(--line, #333); margin-bottom: 16px; flex-wrap: wrap; }',
  '.steg-tab { padding: 8px 16px; cursor: pointer; border: none; background: none; color: var(--mut, #888); font-size: .85rem; border-bottom: 2px solid transparent; transition: all .15s; }',
  '.steg-tab:hover { color: var(--txt, #ccc); }',
  '.steg-tab.on { color: var(--acc, #00d4ff); border-bottom-color: var(--acc, #00d4ff); }',
  '.steg-panel { display: none; }',
  '.steg-panel.on { display: block; }',
  '.steg-drop { border: 2px dashed var(--line, #333); border-radius: 8px; padding: 40px; text-align: center; cursor: pointer; transition: border-color .2s; margin-bottom: 16px; }',
  '.steg-drop:hover, .steg-drop.dragover { border-color: var(--acc, #00d4ff); }',
  '.steg-drop input { display: none; }',
  '.steg-preview { max-width: 100%; max-height: 300px; border-radius: 4px; margin: 8px 0; }',
  '.steg-info { background: var(--card, #161b22); border: 1px solid var(--line, #333); padding: 12px; border-radius: 6px; margin: 8px 0; font-size: .82rem; }',
  '.steg-info td { padding: 3px 12px 3px 0; }',
  '.steg-info .key { color: var(--mut, #888); white-space: nowrap; }',
  '.steg-input { width: 100%; padding: 8px 10px; background: var(--card, #161b22); border: 1px solid var(--line, #333); color: var(--txt, #ccc); border-radius: 4px; font-size: .85rem; }',
  '.steg-input:focus { outline: none; border-color: var(--acc, #00d4ff); }',
  'textarea.steg-input { min-height: 80px; resize: vertical; font-family: monospace; }',
  '.steg-row { display: flex; gap: 12px; align-items: center; margin: 8px 0; flex-wrap: wrap; }',
  '.steg-btn { padding: 8px 18px; background: var(--acc, #00d4ff); color: #000; border: none; border-radius: 4px; cursor: pointer; font-weight: 600; font-size: .85rem; }',
  '.steg-btn:hover { opacity: .85; }',
  '.steg-btn.sec { background: var(--card, #161b22); color: var(--txt, #ccc); border: 1px solid var(--line, #333); }',
  '.steg-result { padding: 12px; border-radius: 6px; margin: 12px 0; font-size: .85rem; }',
  '.steg-result.ok { background: rgba(0,200,80,.12); border: 1px solid rgba(0,200,80,.3); }',
  '.steg-result.err { background: rgba(255,60,60,.12); border: 1px solid rgba(255,60,60,.3); }',
  '.steg-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(120px, 1fr)); gap: 8px; }',
  '.steg-grid canvas { width: 100%; border-radius: 4px; border: 1px solid var(--line, #333); }',
  '.steg-grid-label { font-size: .72rem; color: var(--mut, #888); text-align: center; margin-top: 2px; }',
  '.steg-hist { display: flex; gap: 12px; flex-wrap: wrap; }',
  '.steg-hist canvas { border-radius: 4px; border: 1px solid var(--line, #333); }',
  '.steg-cap-table td { padding: 4px 14px 4px 0; font-size: .85rem; }',
  '.steg-cap-table .val { font-family: monospace; color: var(--acc, #00d4ff); }',
  '.steg-meta-table { width: 100%; border-collapse: collapse; }',
  '.steg-meta-table td { padding: 5px 10px; border-bottom: 1px solid var(--line, #333); font-size: .82rem; }',
  '.steg-meta-table td:first-child { color: var(--mut, #888); white-space: nowrap; width: 160px; }',
  '.steg-binary-out { font-family: monospace; font-size: .8rem; word-break: break-all; line-height: 1.6; padding: 10px; background: var(--card, #161b22); border: 1px solid var(--line, #333); border-radius: 4px; max-height: 200px; overflow-y: auto; }',
  'label.steg-label { font-size: .82rem; color: var(--mut, #888); margin-bottom: 2px; display: block; }',
  '</style>'
].join("\n");

// ── Main render ──
export function renderSteganography(main) {
  var state = {
    canvas: null,
    ctx: null,
    imageData: null,
    originalImageData: null,
    width: 0,
    height: 0,
    fileBytes: null,
    fileName: ""
  };

  var TABS = [
    { id: "encode", label: "Encode" },
    { id: "decode", label: "Decode" },
    { id: "bitplanes", label: "Bit Planes" },
    { id: "analysis", label: "Analysis" },
    { id: "histogram", label: "Histogram" },
    { id: "binary", label: "Text ↔ Binary" },
    { id: "capacity", label: "Capacity" },
    { id: "metadata", label: "Metadata" },
    { id: "headers", label: "File Headers" }
  ];

  var tabsHtml = TABS.map(function(t) {
    return '<button class="steg-tab' + (t.id === "encode" ? " on" : "") + '" data-tab="' + t.id + '">' + esc(t.label) + '</button>';
  }).join("");

  var panelsHtml = TABS.map(function(t) {
    return '<div class="steg-panel' + (t.id === "encode" ? " on" : "") + '" data-panel="' + t.id + '" id="steg-' + t.id + '"></div>';
  }).join("");

  main.innerHTML = STEG_CSS +
    '<div class="steg-wrap">' +
    '<h1 class="pg-h1">Steganography</h1>' +
    '<p class="muted pg-sub">Hide and extract data in images — everything runs in your browser, nothing leaves your machine.</p>' +
    '<div class="steg-drop" id="steg-drop">' +
      '<p style="font-size:1.1rem;margin:0 0 6px">Drop an image here or click to upload</p>' +
      '<p class="muted" style="font-size:.8rem;margin:0">PNG recommended for lossless encoding (JPEG recompression destroys hidden data)</p>' +
      '<input type="file" id="steg-file" accept="image/*">' +
    '</div>' +
    '<div id="steg-preview-area" style="display:none">' +
      '<div class="steg-row"><img id="steg-img-preview" class="steg-preview"><div class="steg-info" id="steg-img-info"></div></div>' +
    '</div>' +
    '<div class="steg-tabs">' + tabsHtml + '</div>' +
    panelsHtml +
    '</div>';

  // ── Image loading ──
  var drop = main.querySelector("#steg-drop");
  var fileInput = main.querySelector("#steg-file");
  var previewArea = main.querySelector("#steg-preview-area");
  var imgPreview = main.querySelector("#steg-img-preview");
  var imgInfo = main.querySelector("#steg-img-info");

  drop.onclick = function() { fileInput.click(); };
  drop.ondragover = function(e) { e.preventDefault(); drop.classList.add("dragover"); };
  drop.ondragleave = function() { drop.classList.remove("dragover"); };
  drop.ondrop = function(e) { e.preventDefault(); drop.classList.remove("dragover"); if (e.dataTransfer.files.length) loadFile(e.dataTransfer.files[0]); };
  fileInput.onchange = function() { if (fileInput.files.length) loadFile(fileInput.files[0]); };

  function loadFile(file) {
    state.fileName = file.name;
    // Read as ArrayBuffer for raw analysis
    var rawReader = new FileReader();
    rawReader.onload = function() {
      state.fileBytes = new Uint8Array(rawReader.result);
      renderMetadata();
      renderHeaders();
    };
    rawReader.readAsArrayBuffer(file);

    // Read as image for canvas
    var imgReader = new FileReader();
    imgReader.onload = function() {
      var img = new Image();
      img.onload = function() {
        state.canvas = document.createElement("canvas");
        state.canvas.width = img.width;
        state.canvas.height = img.height;
        state.width = img.width;
        state.height = img.height;
        state.ctx = state.canvas.getContext("2d");
        state.ctx.drawImage(img, 0, 0);
        state.imageData = state.ctx.getImageData(0, 0, img.width, img.height);
        state.originalImageData = state.ctx.getImageData(0, 0, img.width, img.height);

        imgPreview.src = img.src;
        previewArea.style.display = "";
        imgInfo.innerHTML = '<table>' +
          '<tr><td class="key">File:</td><td>' + esc(file.name) + '</td></tr>' +
          '<tr><td class="key">Dimensions:</td><td>' + img.width + ' x ' + img.height + ' (' + (img.width * img.height).toLocaleString() + ' pixels)</td></tr>' +
          '<tr><td class="key">Size:</td><td>' + (file.size / 1024).toFixed(1) + ' KB</td></tr>' +
          '<tr><td class="key">Type:</td><td>' + esc(file.type) + '</td></tr>' +
          '</table>';

        renderEncode();
        renderDecode();
        renderCapacity();
        renderBitPlanes();
        renderAnalysis();
        renderHistogram();
      };
      img.src = imgReader.result;
    };
    imgReader.readAsDataURL(file);
  }

  // ── Tab switching ──
  main.querySelector(".steg-tabs").onclick = function(e) {
    var btn = e.target.closest(".steg-tab");
    if (!btn) return;
    main.querySelectorAll(".steg-tab").forEach(function(t) { t.classList.toggle("on", t === btn); });
    main.querySelectorAll(".steg-panel").forEach(function(p) { p.classList.toggle("on", p.dataset.panel === btn.dataset.tab); });
  };

  // ── Render panels ──
  function renderEncode() {
    var panel = main.querySelector("#steg-encode");
    panel.innerHTML =
      '<h3 style="margin:0 0 10px">Hide Message in Image</h3>' +
      '<label class="steg-label">Message to hide</label>' +
      '<textarea class="steg-input" id="steg-enc-msg" placeholder="Enter your secret message here..."></textarea>' +
      '<div class="steg-row">' +
        '<div><label class="steg-label">Mode</label><select class="steg-input" id="steg-enc-mode">' +
          '<option value="1">1-bit LSB (most subtle)</option>' +
          '<option value="2">2-bit LSB (more capacity)</option>' +
          '<option value="spread">Spread Spectrum (harder to detect)</option>' +
        '</select></div>' +
        '<div><label class="steg-label">Password (optional)</label><input class="steg-input" id="steg-enc-pw" type="password" placeholder="XOR encryption key"></div>' +
      '</div>' +
      '<div class="steg-row">' +
        '<button class="steg-btn" id="steg-enc-go">Encode Message</button>' +
        '<button class="steg-btn sec" id="steg-enc-dl" style="display:none">Download Stego Image (PNG)</button>' +
      '</div>' +
      '<div id="steg-enc-result"></div>';

    var goBtn = panel.querySelector("#steg-enc-go");
    var dlBtn = panel.querySelector("#steg-enc-dl");

    goBtn.onclick = function() {
      if (!state.imageData) { showResult(panel, "err", "Load an image first."); return; }
      var msg = panel.querySelector("#steg-enc-msg").value;
      if (!msg) { showResult(panel, "err", "Enter a message to hide."); return; }
      var mode = panel.querySelector("#steg-enc-mode").value;
      var pw = panel.querySelector("#steg-enc-pw").value;

      // Work on a fresh copy
      var fresh = state.ctx.getImageData(0, 0, state.width, state.height);
      var origData = state.originalImageData.data;
      for (var i = 0; i < origData.length; i++) fresh.data[i] = origData[i];

      var result;
      if (mode === "spread") {
        result = spreadEncode(fresh, msg, pw, 7);
      } else {
        result = lsbEncode(fresh, msg, parseInt(mode), pw);
      }

      if (!result.success) {
        showResult(panel, "err", result.error);
        return;
      }

      state.imageData = fresh;
      state.ctx.putImageData(fresh, 0, 0);
      imgPreview.src = state.canvas.toDataURL("image/png");

      showResult(panel, "ok",
        "Message encoded successfully! " + result.bitsUsed + " bits used of " + result.capacity + " capacity (" +
        (result.bitsUsed / result.capacity * 100).toFixed(1) + "% full). Download as PNG to preserve the hidden data.");

      dlBtn.style.display = "";
      dlBtn.onclick = function() {
        var a = document.createElement("a");
        a.href = state.canvas.toDataURL("image/png");
        a.download = "stego_" + state.fileName.replace(/\.[^.]+$/, "") + ".png";
        a.click();
      };
    };
  }

  function renderDecode() {
    var panel = main.querySelector("#steg-decode");
    panel.innerHTML =
      '<h3 style="margin:0 0 10px">Extract Hidden Message</h3>' +
      '<div class="steg-row">' +
        '<div><label class="steg-label">Mode</label><select class="steg-input" id="steg-dec-mode">' +
          '<option value="1">1-bit LSB</option>' +
          '<option value="2">2-bit LSB</option>' +
          '<option value="spread">Spread Spectrum</option>' +
        '</select></div>' +
        '<div><label class="steg-label">Password (if encrypted)</label><input class="steg-input" id="steg-dec-pw" type="password" placeholder="Leave empty if none"></div>' +
      '</div>' +
      '<button class="steg-btn" id="steg-dec-go">Extract Message</button>' +
      '<div id="steg-dec-result"></div>' +
      '<div id="steg-dec-msg-out" style="display:none">' +
        '<label class="steg-label" style="margin-top:12px">Extracted message:</label>' +
        '<textarea class="steg-input" id="steg-dec-text" readonly style="min-height:100px"></textarea>' +
      '</div>';

    panel.querySelector("#steg-dec-go").onclick = function() {
      if (!state.imageData) { showResult(panel, "err", "Load an image first."); return; }
      var mode = panel.querySelector("#steg-dec-mode").value;
      var pw = panel.querySelector("#steg-dec-pw").value;

      var result;
      if (mode === "spread") {
        result = spreadDecode(state.imageData, pw, 7);
      } else {
        result = lsbDecode(state.imageData, parseInt(mode), pw);
      }

      var msgOut = panel.querySelector("#steg-dec-msg-out");
      if (!result.success) {
        showResult(panel, "err", result.error);
        msgOut.style.display = "none";
        return;
      }
      showResult(panel, "ok", "Message found! Length: " + result.length + " characters.");
      msgOut.style.display = "";
      panel.querySelector("#steg-dec-text").value = result.message;
    };
  }

  function renderBitPlanes() {
    var panel = main.querySelector("#steg-bitplanes");
    if (!state.imageData) {
      panel.innerHTML = '<p class="muted">Load an image to view bit planes.</p>';
      return;
    }
    var channelNames = ["Red", "Green", "Blue"];
    var html = '<h3 style="margin:0 0 10px">Bit Plane Analysis</h3>' +
      '<p class="muted" style="font-size:.82rem;margin-bottom:12px">Each image shows one bit of one color channel. The LSB planes (bit 0) are where steganographic data hides — random-looking LSB planes may indicate hidden data.</p>';

    panel.innerHTML = html + '<div class="steg-grid" id="steg-bp-grid"></div>';

    var grid = panel.querySelector("#steg-bp-grid");
    for (var ch = 0; ch < 3; ch++) {
      for (var bit = 0; bit < 8; bit++) {
        var bpCanvas = extractBitPlane(state.imageData, ch, bit);
        var label = channelNames[ch] + " bit " + bit + (bit === 0 ? " (LSB)" : bit === 7 ? " (MSB)" : "");
        var wrap = document.createElement("div");
        wrap.appendChild(bpCanvas);
        var lbl = document.createElement("div");
        lbl.className = "steg-grid-label";
        lbl.textContent = label;
        wrap.appendChild(lbl);
        grid.appendChild(wrap);
      }
    }
  }

  function renderAnalysis() {
    var panel = main.querySelector("#steg-analysis");
    if (!state.imageData) {
      panel.innerHTML = '<p class="muted">Load an image to run analysis.</p>';
      return;
    }

    var rChi = chiSquareAnalysis(state.imageData, 0);
    var gChi = chiSquareAnalysis(state.imageData, 1);
    var bChi = chiSquareAnalysis(state.imageData, 2);

    var html = '<h3 style="margin:0 0 10px">Steganalysis</h3>' +
      '<p class="muted" style="font-size:.82rem;margin-bottom:12px">Chi-square analysis tests whether pixel value pairs are suspiciously uniform — a hallmark of LSB steganography. Low p-values suggest hidden data.</p>' +
      '<table class="steg-meta-table">' +
      '<tr><td>Red channel</td><td>&chi;&sup2; = ' + rChi.chiSquare.toFixed(2) + ', p = ' + rChi.pValue.toFixed(4) + (rChi.suspicious ? ' <span style="color:#f44">SUSPICIOUS</span>' : ' <span style="color:#4f4">Normal</span>') + '</td></tr>' +
      '<tr><td>Green channel</td><td>&chi;&sup2; = ' + gChi.chiSquare.toFixed(2) + ', p = ' + gChi.pValue.toFixed(4) + (gChi.suspicious ? ' <span style="color:#f44">SUSPICIOUS</span>' : ' <span style="color:#4f4">Normal</span>') + '</td></tr>' +
      '<tr><td>Blue channel</td><td>&chi;&sup2; = ' + bChi.chiSquare.toFixed(2) + ', p = ' + bChi.pValue.toFixed(4) + (bChi.suspicious ? ' <span style="color:#f44">SUSPICIOUS</span>' : ' <span style="color:#4f4">Normal</span>') + '</td></tr>' +
      '</table>';

    // Overall assessment
    var anyBad = rChi.suspicious || gChi.suspicious || bChi.suspicious;
    html += '<div class="steg-result ' + (anyBad ? "err" : "ok") + '">' +
      (anyBad ? 'One or more channels show statistical anomalies consistent with LSB steganography.' : 'No statistical evidence of LSB steganography detected.') +
      '</div>';

    // Entropy per channel
    var rEnt = calculateEntropy(state.imageData.data, 0, state.imageData.data.length);
    html += '<h4 style="margin:16px 0 8px">Data Entropy</h4>' +
      '<table class="steg-meta-table">' +
      '<tr><td>Overall entropy</td><td>' + rEnt.toFixed(4) + ' bits/byte' + (rEnt > 7.5 ? ' (very high)' : rEnt > 6 ? ' (moderate)' : ' (low)') + '</td></tr>' +
      '<tr><td>Pixels</td><td>' + (state.width * state.height).toLocaleString() + '</td></tr>' +
      '<tr><td>Data bytes</td><td>' + state.imageData.data.length.toLocaleString() + '</td></tr>' +
      '</table>';

    panel.innerHTML = html;
  }

  function renderHistogram() {
    var panel = main.querySelector("#steg-histogram");
    if (!state.imageData) {
      panel.innerHTML = '<p class="muted">Load an image to view histograms.</p>';
      return;
    }
    panel.innerHTML = '<h3 style="margin:0 0 10px">Color Histogram</h3>' +
      '<p class="muted" style="font-size:.82rem;margin-bottom:12px">RGB value distribution. LSB steganography flattens the distribution of value pairs — compare original vs. modified.</p>' +
      '<div class="steg-hist" id="steg-hist-area"></div>';

    var area = panel.querySelector("#steg-hist-area");
    var origHist = computeHistogram(state.originalImageData);
    var curHist = computeHistogram(state.imageData);

    var c1 = document.createElement("canvas");
    c1.width = 512; c1.height = 180;
    drawHistogram(c1, origHist, "Original");
    area.appendChild(c1);

    var c2 = document.createElement("canvas");
    c2.width = 512; c2.height = 180;
    drawHistogram(c2, curHist, "Current");
    area.appendChild(c2);
  }

  function renderCapacity() {
    var panel = main.querySelector("#steg-capacity");
    if (!state.imageData) {
      panel.innerHTML =
        '<h3 style="margin:0 0 10px">Capacity Calculator</h3>' +
        '<div class="steg-row">' +
          '<div><label class="steg-label">Width</label><input class="steg-input" id="steg-cap-w" type="number" value="1920"></div>' +
          '<div><label class="steg-label">Height</label><input class="steg-input" id="steg-cap-h" type="number" value="1080"></div>' +
        '</div>' +
        '<div id="steg-cap-out"></div>';
    } else {
      panel.innerHTML =
        '<h3 style="margin:0 0 10px">Capacity Calculator</h3>' +
        '<div class="steg-row">' +
          '<div><label class="steg-label">Width</label><input class="steg-input" id="steg-cap-w" type="number" value="' + state.width + '"></div>' +
          '<div><label class="steg-label">Height</label><input class="steg-input" id="steg-cap-h" type="number" value="' + state.height + '"></div>' +
        '</div>' +
        '<div id="steg-cap-out"></div>';
    }

    function updateCap() {
      var w = parseInt(panel.querySelector("#steg-cap-w").value) || 0;
      var h = parseInt(panel.querySelector("#steg-cap-h").value) || 0;
      if (w <= 0 || h <= 0) return;

      var modes = [
        { label: "1-bit LSB", bpc: 1, mode: "lsb" },
        { label: "2-bit LSB", bpc: 2, mode: "lsb" },
        { label: "Spread Spectrum (7x)", bpc: 1, mode: "spread" }
      ];

      var html = '<table class="steg-cap-table">' +
        '<tr style="color:var(--mut)"><td>Mode</td><td>Capacity (bytes)</td><td>Capacity (KB)</td><td>Capacity (chars)</td></tr>';
      for (var i = 0; i < modes.length; i++) {
        var cap = calcCapacity(w, h, modes[i].bpc, modes[i].mode);
        html += '<tr><td>' + modes[i].label + '</td><td class="val">' + cap.bytes.toLocaleString() + '</td><td class="val">' + cap.kb + '</td><td class="val">' + cap.chars.toLocaleString() + '</td></tr>';
      }
      html += '</table>';
      panel.querySelector("#steg-cap-out").innerHTML = html;
    }

    panel.querySelector("#steg-cap-w").oninput = updateCap;
    panel.querySelector("#steg-cap-h").oninput = updateCap;
    updateCap();
  }

  // ── Text ↔ Binary ──
  (function() {
    var panel = main.querySelector("#steg-binary");
    panel.innerHTML =
      '<h3 style="margin:0 0 10px">Text ↔ Binary Converter</h3>' +
      '<div class="steg-row" style="align-items:flex-start">' +
        '<div style="flex:1"><label class="steg-label">Text</label><textarea class="steg-input" id="steg-bin-text" placeholder="Enter text..."></textarea></div>' +
        '<div style="display:flex;flex-direction:column;gap:4px;padding-top:20px">' +
          '<button class="steg-btn" id="steg-bin-to" style="font-size:.75rem">Text → Binary</button>' +
          '<button class="steg-btn sec" id="steg-bin-from" style="font-size:.75rem">Binary → Text</button>' +
        '</div>' +
        '<div style="flex:1"><label class="steg-label">Binary (8-bit groups)</label><textarea class="steg-input" id="steg-bin-bits" placeholder="01001000 01100101 01101100 01101100 01101111"></textarea></div>' +
      '</div>' +
      '<div class="steg-row">' +
        '<div style="flex:1"><label class="steg-label">Hex</label><input class="steg-input" id="steg-bin-hex" placeholder="48 65 6C 6C 6F"></div>' +
        '<div style="flex:1"><label class="steg-label">Decimal</label><input class="steg-input" id="steg-bin-dec" placeholder="72 101 108 108 111"></div>' +
      '</div>';

    panel.querySelector("#steg-bin-to").onclick = function() {
      var text = panel.querySelector("#steg-bin-text").value;
      var binGroups = [];
      var hexGroups = [];
      var decGroups = [];
      for (var i = 0; i < text.length; i++) {
        var code = text.charCodeAt(i);
        var bin = "";
        for (var b = 7; b >= 0; b--) bin += ((code >> b) & 1);
        binGroups.push(bin);
        hexGroups.push(code.toString(16).toUpperCase().padStart(2, "0"));
        decGroups.push(code.toString());
      }
      panel.querySelector("#steg-bin-bits").value = binGroups.join(" ");
      panel.querySelector("#steg-bin-hex").value = hexGroups.join(" ");
      panel.querySelector("#steg-bin-dec").value = decGroups.join(" ");
    };

    panel.querySelector("#steg-bin-from").onclick = function() {
      var bits = panel.querySelector("#steg-bin-bits").value.replace(/\s/g, "");
      var text = "";
      for (var i = 0; i + 7 < bits.length; i += 8) {
        var byte = parseInt(bits.substring(i, i + 8), 2);
        if (byte > 0) text += String.fromCharCode(byte);
      }
      panel.querySelector("#steg-bin-text").value = text;
      // Also update hex and decimal
      var hexGroups = [];
      var decGroups = [];
      for (var j = 0; j < text.length; j++) {
        var code = text.charCodeAt(j);
        hexGroups.push(code.toString(16).toUpperCase().padStart(2, "0"));
        decGroups.push(code.toString());
      }
      panel.querySelector("#steg-bin-hex").value = hexGroups.join(" ");
      panel.querySelector("#steg-bin-dec").value = decGroups.join(" ");
    };
  })();

  function renderMetadata() {
    var panel = main.querySelector("#steg-metadata");
    if (!state.fileBytes) {
      panel.innerHTML = '<p class="muted">Load an image to view metadata.</p>';
      return;
    }
    var meta = readImageMetadata(state.fileBytes);
    var html = '<h3 style="margin:0 0 10px">Image Metadata</h3>' +
      '<table class="steg-meta-table">';
    for (var i = 0; i < meta.length; i++) {
      html += '<tr><td>' + esc(meta[i].key) + '</td><td>' + esc(meta[i].value) + '</td></tr>';
    }
    html += '</table>';
    panel.innerHTML = html;
  }

  function renderHeaders() {
    var panel = main.querySelector("#steg-headers");
    if (!state.fileBytes) {
      panel.innerHTML = '<p class="muted">Load a file to analyze headers.</p>';
      return;
    }
    var bytes = state.fileBytes;
    var sig = detectFileType(bytes);

    var html = '<h3 style="margin:0 0 10px">File Header Analysis</h3>';
    html += '<div class="steg-info"><table>';
    html += '<tr><td class="key">Detected Type:</td><td>' + (sig ? esc(sig.name) : "Unknown") + '</td></tr>';
    html += '<tr><td class="key">Magic Bytes:</td><td style="font-family:monospace">';
    var magicLen = Math.min(16, bytes.length);
    for (var i = 0; i < magicLen; i++) {
      html += bytes[i].toString(16).toUpperCase().padStart(2, "0") + " ";
    }
    html += '</td></tr>';
    html += '</table></div>';

    // Hex dump of first 256 bytes
    html += '<h4 style="margin:14px 0 8px">First 256 bytes (hex dump)</h4>';
    html += '<div class="steg-binary-out">';
    var lineLen = 16;
    var dumpLen = Math.min(256, bytes.length);
    for (var row = 0; row < dumpLen; row += lineLen) {
      var addr = row.toString(16).toUpperCase().padStart(8, "0");
      var hexPart = "";
      var ascPart = "";
      for (var col = 0; col < lineLen; col++) {
        if (row + col < dumpLen) {
          hexPart += bytes[row + col].toString(16).toUpperCase().padStart(2, "0") + " ";
          var ch = bytes[row + col];
          ascPart += (ch >= 32 && ch < 127) ? String.fromCharCode(ch) : ".";
        } else {
          hexPart += "   ";
          ascPart += " ";
        }
        if (col === 7) hexPart += " ";
      }
      html += '<span style="color:var(--acc)">' + addr + '</span>  ' + hexPart + ' <span style="color:var(--mut)">' + esc(ascPart) + '</span>\n';
    }
    html += '</div>';

    // Appended data check
    var appended = findAppendedData(bytes);
    if (appended) {
      html += '<div class="steg-result err">Appended data detected: ' + appended.size.toLocaleString() + ' bytes after EOF marker at offset 0x' + appended.offset.toString(16).toUpperCase() + '. This could indicate hidden data appended after the image.</div>';

      html += '<h4 style="margin:14px 0 8px">Appended data (first 128 bytes)</h4>';
      html += '<div class="steg-binary-out">';
      var appStart = appended.offset;
      var appEnd = Math.min(appStart + 128, bytes.length);
      for (var aRow = appStart; aRow < appEnd; aRow += lineLen) {
        var aAddr = aRow.toString(16).toUpperCase().padStart(8, "0");
        var aHex = "";
        var aAsc = "";
        for (var aCol = 0; aCol < lineLen; aCol++) {
          if (aRow + aCol < appEnd) {
            aHex += bytes[aRow + aCol].toString(16).toUpperCase().padStart(2, "0") + " ";
            var aCh = bytes[aRow + aCol];
            aAsc += (aCh >= 32 && aCh < 127) ? String.fromCharCode(aCh) : ".";
          } else {
            aHex += "   "; aAsc += " ";
          }
          if (aCol === 7) aHex += " ";
        }
        html += '<span style="color:var(--acc)">' + aAddr + '</span>  ' + aHex + ' <span style="color:var(--mut)">' + esc(aAsc) + '</span>\n';
      }
      html += '</div>';
    } else {
      html += '<div class="steg-result ok">No appended data detected after EOF marker.</div>';
    }

    // Known signature table
    html += '<h4 style="margin:14px 0 8px">File Signature Database</h4>' +
      '<table class="steg-meta-table">';
    for (var s = 0; s < FILE_SIGNATURES.length; s++) {
      var fs = FILE_SIGNATURES[s];
      html += '<tr><td>' + esc(fs.name) + '</td><td style="font-family:monospace">' +
        fs.magic.map(function(b) { return b.toString(16).toUpperCase().padStart(2, "0"); }).join(" ") +
        '</td></tr>';
    }
    html += '</table>';

    panel.innerHTML = html;
  }

  function showResult(panel, type, msg) {
    var el = panel.querySelector("[id$='-result']") || panel.querySelector(".steg-result");
    if (!el) {
      el = document.createElement("div");
      panel.appendChild(el);
    }
    el.className = "steg-result " + type;
    el.textContent = msg;
  }
}
