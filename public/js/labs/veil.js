// ============================================================================
// Veil — Onion Playground (Labs demo, real cryptography)
//
// This is NOT a simulation. Every operation below runs real WebCrypto:
//   - each relay holds a real ECDH (NIST P-256) key pair
//   - the client wraps the message in real layered AES-256-GCM, one layer per
//     hop, with per-hop keys derived via ECDH -> HKDF-SHA256
//   - each relay peels exactly one layer by really decrypting it; it learns only
//     the next hop, never the origin or (except the exit) the content
//   - fixed-size payload cells hide the message length; a replay cache rejects a
//     re-sent onion
//
// Veil is a research prototype for learning privacy engineering — it is not a
// production anonymity network and must not be relied on for real-world safety.
// Post-quantum hybrid handshake (X25519 + ML-KEM) and a real local mixnet are
// separate modules on the roadmap (docs/veil-demo-plan.md).
//
//   renderVeil(main) -> void
// ============================================================================

import { dnFetch, proxyConfigured } from "/js/net.js";

const ACK_KEY = "dn_veil_ack_v1";
// Some public sites (Ahmia) deflect bot User-Agents with a 302; the edge proxy
// honors an opt-in browser UA so these real lookups return real pages.
const BROWSER_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36";
const CELL = 512;                 // fixed payload-cell size (bytes); hides length
const enc = (s) => new TextEncoder().encode(s);
const dec = (b) => new TextDecoder().decode(b);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const sub = () => crypto.subtle;
const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
const short = (h, n = 10) => h.length > n * 2 ? h.slice(0, n) + "…" + h.slice(-n) : h;
function concat(...arrs) { let n = 0; for (const a of arrs) n += a.length; const o = new Uint8Array(n); let i = 0; for (const a of arrs) { o.set(a, i); i += a.length; } return o; }
function u32(n) { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; }
function ru32(b, o) { return new DataView(b.buffer, b.byteOffset).getUint32(o); }

function toast(m) { try { (window.dnToast || window.showToast || (() => {}))(m); } catch (_) {} }

// ---- real crypto primitives ----
async function genKey() {
  const kp = await sub().generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveBits"]);
  const pubRaw = new Uint8Array(await sub().exportKey("raw", kp.publicKey));
  return { priv: kp.privateKey, pubRaw };
}
// Derive a per-hop AES-256-GCM key from ECDH(myPriv, theirPub) via HKDF-SHA256.
// Salt is the ephemeral public key (known to both sides), info pins the context.
async function deriveAes(myPriv, theirPubRaw, saltRaw) {
  const theirPub = await sub().importKey("raw", theirPubRaw, { name: "ECDH", namedCurve: "P-256" }, false, []);
  const sharedBits = await sub().deriveBits({ name: "ECDH", public: theirPub }, myPriv, 256);
  const hk = await sub().importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  return sub().deriveKey({ name: "HKDF", hash: "SHA-256", salt: saltRaw, info: enc("veil-onion-v1") }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
// packet := eph(65) || iv(12) || ctLen(4) || ct
function packPacket(ephRaw, iv, ct) { return concat(ephRaw, iv, u32(ct.length), ct); }
function unpackPacket(b) { const eph = b.slice(0, 65), iv = b.slice(65, 77), clen = ru32(b, 77), ct = b.slice(81, 81 + clen); return { eph, iv, ct }; }
// fixed payload cell := msgLen(4) || msg || random pad (to a multiple of CELL)
function padCell(msgBytes) { const need = msgBytes.length + 4; const size = Math.max(CELL, Math.ceil(need / CELL) * CELL); return concat(u32(msgBytes.length), msgBytes, rand(size - need)); }
function unpadCell(cell) { const n = ru32(cell, 0); return cell.slice(4, 4 + n); }

// Build the onion: wrap the message in one real AES-GCM layer per hop, inside out.
// The layer encrypted FOR relay i carries the NEXT hop's label + the inner packet.
async function buildOnion(message, relays) {
  let inner = padCell(enc(message)), label = "EXIT", cell = inner.length;
  const layers = [];
  for (let i = relays.length - 1; i >= 0; i--) {
    const eph = await genKey();
    const key = await deriveAes(eph.priv, relays[i].pubRaw, eph.pubRaw);
    const plain = concat(new Uint8Array([label.length]), enc(label), inner);
    const iv = rand(12);
    const ct = new Uint8Array(await sub().encrypt({ name: "AES-GCM", iv }, key, plain));
    const pkt = packPacket(eph.pubRaw, iv, ct);
    layers.unshift({ forHop: i, ephRaw: eph.pubRaw, bytes: pkt.length });
    inner = pkt;
    label = relays[i].name;
  }
  return { onion: inner, layers, cell };
}

// Peel the onion through the relays — each really decrypts its own layer.
async function peelOnion(onion, relays) {
  const steps = []; let pkt = onion, recovered = null, failed = false;
  for (let i = 0; i < relays.length; i++) {
    const r = relays[i];
    const { eph, iv, ct } = unpackPacket(pkt);
    const ephHex = hex(eph);
    if (r.seen.has(ephHex)) { steps.push({ hop: i, replay: true, ephHex }); failed = true; break; }
    r.seen.add(ephHex);
    let plain;
    try { plain = new Uint8Array(await sub().decrypt({ name: "AES-GCM", iv }, await deriveAes(r.priv, eph, eph), ct)); }
    catch (e) { steps.push({ hop: i, error: true, ephHex }); failed = true; break; }
    const ll = plain[0], label = dec(plain.slice(1, 1 + ll)), body = plain.slice(1 + ll);
    const isExit = label === "EXIT";
    steps.push({ hop: i, ephHex, next: isExit ? null : label, size: pkt.length, exit: isExit });
    if (isExit) { recovered = dec(unpadCell(body)); break; }
    pkt = body;
  }
  return { steps, recovered, failed };
}

// ---- styling (light lab panels; matches the console's pro theme) ----
function injectCSS() {
  if (document.getElementById("veil-css")) return;
  const s = document.createElement("style"); s.id = "veil-css";
  s.textContent = `
  .vl{--panel:#ffffff;--panel2:#f5f7fb;--code:#f3f6fb;--bd:#e5e8f0;--bd2:#d3d9e6;--tx:#1a2233;--mut:#687388;--ac:#2f63e0;--ok:#12a85f;--warn:#b7791f;--bad:#d9443f;color:var(--tx);max-width:1180px}
  .vl *{box-sizing:border-box}
  .vl-gate{max-width:720px;margin:4vh auto;background:var(--panel);border:1px solid var(--bd);border-radius:16px;padding:30px 30px 26px;box-shadow:0 1px 3px rgba(20,30,60,.05)}
  .vl-gate .ico{width:46px;height:46px;border-radius:12px;display:grid;place-items:center;background:#fdecec;border:1px solid #f4caca;color:#d9443f;margin-bottom:16px}
  .vl-gate h1{font-size:23px;margin:0 0 6px;color:#141c2e}
  .vl-gate .lede{color:#45506a;font-size:14px;line-height:1.6;margin:0 0 16px}
  .vl-warn{background:#fdf6e7;border:1px solid #f0dca6;border-radius:11px;padding:14px 16px;color:#7a5a16;font-size:12.5px;line-height:1.6;margin-bottom:18px}
  .vl-warn b{color:#5e440f}
  .vl-gate .acts{display:flex;gap:10px;flex-wrap:wrap}
  .vl-hero{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;flex-wrap:wrap;margin:2px 0 18px}
  .vl-hero h1{font-size:25px;margin:0 0 4px;letter-spacing:-.01em;color:#141c2e}
  .vl-hero p{margin:0;color:var(--mut);font-size:13px;max-width:640px;line-height:1.5}
  .vl-badges{display:flex;gap:7px;flex-wrap:wrap;margin-top:10px}
  .vl-badge{font-size:10.5px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:4px 9px;border-radius:20px;border:1px solid var(--bd2);color:#51607e;background:#f6f8fc}
  .vl-badge.ok{color:#0e7a45;border-color:#b6e6cc;background:#eafaf1}
  .vl-grid{display:grid;grid-template-columns:360px 1fr;gap:16px;align-items:start}
  @media(max-width:900px){.vl-grid{grid-template-columns:1fr}}
  .vl-card{background:var(--panel);border:1px solid var(--bd);border-radius:14px;padding:16px 17px;box-shadow:0 1px 3px rgba(20,30,60,.04)}
  .vl-card h2{font-size:13px;letter-spacing:.03em;text-transform:uppercase;color:#5a6680;margin:0 0 12px;font-weight:700}
  .vl-field{margin-bottom:14px}
  .vl-field label{display:block;font-size:12px;font-weight:600;color:#38435c;margin-bottom:6px}
  .vl-field textarea,.vl-field input,.vl-field select{width:100%;background:#fff;border:1px solid var(--bd2);border-radius:9px;color:var(--tx);font:inherit;font-size:13px;padding:10px 12px;outline:none;resize:vertical}
  .vl-field textarea{min-height:80px;line-height:1.5}
  .vl-field textarea::placeholder,.vl-field input::placeholder{color:#9aa4ba;text-overflow:ellipsis}
  .vl-field input:focus,.vl-field textarea:focus,.vl-field select:focus{border-color:var(--ac);box-shadow:0 0 0 3px rgba(47,99,224,.12)}
  .vl-hint{display:block;font-size:11.5px;color:var(--mut);line-height:1.5;margin-top:6px;white-space:normal;overflow-wrap:anywhere}
  .vl-row{display:flex;gap:10px;flex-wrap:wrap}
  .vl-row .vl-field{flex:1;min-width:0}
  .vl-btn{appearance:none;border:1px solid var(--bd2);background:#fff;color:#38435c;font:inherit;font-size:13px;font-weight:600;padding:9px 15px;border-radius:9px;cursor:pointer;display:inline-flex;align-items:center;gap:7px;transition:background .15s,border-color .15s;text-decoration:none}
  .vl-btn:hover{background:#f2f5fb;border-color:#c2cad9}
  .vl-btn.pri{background:var(--ac);border-color:var(--ac);color:#fff}
  .vl-btn.pri:hover{background:#2552c6}
  .vl-btn:disabled{opacity:.5;cursor:not-allowed}
  .vl-acts{display:flex;gap:9px;flex-wrap:wrap;margin-top:4px}
  .vl-relays{display:flex;flex-direction:column;gap:8px;margin-top:4px}
  .vl-relay{display:flex;align-items:center;gap:10px;background:var(--panel2);border:1px solid var(--bd);border-radius:10px;padding:9px 12px}
  .vl-relay .n{width:30px;height:30px;border-radius:8px;display:grid;place-items:center;font-size:12px;font-weight:700;background:#e4ecfd;color:#2f63e0;flex:none}
  .vl-relay.exit .n{background:#e2f7ec;color:#12a85f}
  .vl-relay .m{min-width:0}
  .vl-relay .m b{display:block;font-size:12.5px;color:#1a2233}
  .vl-relay .m code{font-size:11px;color:#6a7488;font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
  .vl-onion{background:var(--code);border:1px solid var(--bd);border-radius:11px;padding:13px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#2b6a4e;line-height:1.7;word-break:break-all;overflow-wrap:anywhere}
  .vl-onion .lbl{color:#8a93a6}
  .vl-steps{display:flex;flex-direction:column;gap:10px}
  .vl-step{background:var(--panel2);border:1px solid var(--bd);border-left:3px solid var(--ac);border-radius:10px;padding:11px 14px;opacity:0;transform:translateY(5px);transition:opacity .25s,transform .25s}
  .vl-step.in{opacity:1;transform:none}
  .vl-step.exit{border-left-color:var(--ok)}
  .vl-step.bad{border-left-color:var(--bad)}
  .vl-step .sh{display:flex;align-items:center;gap:9px;margin-bottom:5px}
  .vl-step .sh .hp{font-size:12.5px;font-weight:700;color:#1a2233}
  .vl-step .sh .tag{margin-left:auto;font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;padding:2px 8px;border-radius:20px;background:#eef1f7;color:#5a6680}
  .vl-step .sh .tag.ok{background:#e2f7ec;color:#0e7a45}
  .vl-step .sh .tag.bad{background:#fdecec;color:#c13a36}
  .vl-step .sl{font-size:12px;color:#44506a;line-height:1.55}
  .vl-step .sl code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11px;color:#2552c6;background:#e9effb;padding:1px 6px;border-radius:5px;overflow-wrap:anywhere}
  .vl-step .msg{margin-top:7px;background:#eafaf1;border:1px solid #bfe8d0;border-radius:8px;padding:9px 11px;color:#0e7a45;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;word-break:break-word;white-space:pre-wrap}
  .vl-know{width:100%;border-collapse:collapse;font-size:12px;margin-top:6px}
  .vl-know th,.vl-know td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd)}
  .vl-know th{font-size:10.5px;letter-spacing:.04em;text-transform:uppercase;color:#6a7488;font-weight:700}
  .vl-know td{color:#38435c}
  .vl-know .y{color:#c13a36;font-weight:600}
  .vl-know .n{color:#0e7a45;font-weight:600}
  .vl-note{font-size:11.5px;color:var(--mut);line-height:1.6;margin-top:12px;border-top:1px solid var(--bd);padding-top:12px}
  .vl-note b{color:#38435c}
  .vl-empty{color:var(--mut);font-size:13px;text-align:center;padding:36px 16px;line-height:1.6}
  .vl-kpis{display:flex;gap:10px;flex-wrap:wrap;margin:0 0 14px}
  .vl-kpi{flex:1;min-width:120px;background:var(--panel2);border:1px solid var(--bd);border-radius:10px;padding:10px 13px}
  .vl-kpi b{display:block;font-size:18px;color:#141c2e;font-variant-numeric:tabular-nums}
  .vl-kpi span{font-size:11px;color:var(--mut)}
  .vl-tabs{display:flex;gap:4px;margin:14px 0 18px;border-bottom:1px solid var(--bd);flex-wrap:wrap}
  .vl-tab{appearance:none;border:0;background:none;font:inherit;font-size:13px;font-weight:600;color:var(--mut);padding:9px 14px;cursor:pointer;border-bottom:2px solid transparent;margin-bottom:-1px}
  .vl-tab:hover{color:#38435c}
  .vl-tab.on{color:var(--ac);border-bottom-color:var(--ac)}
  .vl-bar{display:flex;gap:9px;flex-wrap:wrap;align-items:flex-start}
  .vl-bar .vl-field{flex:1;min-width:220px;margin-bottom:0}
  .vl-banner{background:#eef3fc;border:1px solid #d3e0f5;border-radius:11px;padding:12px 15px;color:#33507e;font-size:12.5px;line-height:1.6;margin-bottom:16px}
  .vl-banner b{color:#1e3a66}
  .vl-res{display:flex;flex-direction:column;gap:10px;margin-top:16px}
  .vl-hit{background:var(--panel);border:1px solid var(--bd);border-radius:12px;padding:13px 15px;box-shadow:0 1px 3px rgba(20,30,60,.04)}
  .vl-hit h3{margin:0 0 4px;font-size:14px;color:#141c2e;line-height:1.35;word-break:break-word}
  .vl-hit .on{display:flex;align-items:center;gap:8px;margin:4px 0 7px}
  .vl-hit .on code{flex:1;min-width:0;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#2b6a4e;word-break:break-all;background:var(--code);border:1px solid var(--bd);border-radius:7px;padding:5px 8px}
  .vl-hit .on .vl-btn{flex:none;padding:6px 11px;font-size:12px}
  .vl-hit p{margin:0;font-size:12.5px;color:#44506a;line-height:1.55;word-break:break-word}
  .vl-meta{display:flex;gap:8px;flex-wrap:wrap;margin:12px 0}
  .vl-pill{font-size:11px;font-weight:600;padding:4px 9px;border-radius:7px;background:var(--panel2);border:1px solid var(--bd);color:#44506a;font-family:ui-monospace,Menlo,Consolas,monospace}
  .vl-pill.ok{background:#eafaf1;border-color:#bfe8d0;color:#0e7a45}
  .vl-pill.bad{background:#fdecec;border-color:#f4caca;color:#c13a36}
  .vl-frame{width:100%;height:560px;border:1px solid var(--bd);border-radius:12px;background:#fff}
  .vl-src{margin:0;background:var(--code);border:1px solid var(--bd);border-radius:11px;padding:13px 14px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:11.5px;color:#334;line-height:1.6;max-height:560px;overflow:auto;white-space:pre-wrap;word-break:break-word}
  .vl-spin{display:inline-block;width:14px;height:14px;border:2px solid currentColor;border-right-color:transparent;border-radius:50%;animation:vlspin .7s linear infinite;vertical-align:-2px;margin-right:7px}
  @keyframes vlspin{to{transform:rotate(360deg)}}
  .vl-err{background:#fdecec;border:1px solid #f4caca;border-radius:11px;padding:13px 15px;color:#a3302c;font-size:12.5px;line-height:1.6}
  `;
  document.head.appendChild(s);
}

const SHIELD = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l7 3v5c0 4.5-3 7.5-7 9-4-1.5-7-4.5-7-9V6l7-3Z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>';
const WARN = '<svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 2 20h20L12 3Z"/><path d="M12 10v5M12 18h.01"/></svg>';

export function renderVeil(main) {
  injectCSS();
  let acked = false;
  try { acked = localStorage.getItem(ACK_KEY) === "1"; } catch (_) {}
  if (!acked) return renderGate(main);
  renderLab(main);
}

function renderGate(main) {
  main.innerHTML = `
  <div class="vl">
    <div class="vl-gate">
      <div class="ico">${WARN}</div>
      <h1>Veil — privacy engineering lab</h1>
      <p class="lede">Veil is a hands-on demo of next-generation privacy technology. It runs <b>real cryptography</b> in your browser — real ECDH key agreement and real layered AES-256-GCM onion encryption, peeled hop by hop. Nothing here is faked.</p>
      <div class="vl-warn">
        <b>This is a research prototype, not Tor.</b> Its strength is the cryptography, not an anonymity network — there is no large relay set behind it. <b>Do not rely on Veil to protect you in a real-world, threat-to-life situation.</b> Use it only to learn how these systems work, and only for lawful, authorized research.
      </div>
      <div class="acts">
        <button class="vl-btn pri" id="vlAck">I understand — enter the lab</button>
      </div>
    </div>
  </div>`;
  const ack = main.querySelector("#vlAck");
  if (ack) ack.onclick = () => { try { localStorage.setItem(ACK_KEY, "1"); } catch (_) {} renderLab(main); };
}

function renderOnionLab(main) {
  main.innerHTML = `
    <p class="vl-note" style="border-top:0;margin-top:0;padding-top:0">Wrap a message in real, layered end-to-end encryption and watch each relay peel exactly one layer. Every operation is genuine WebCrypto — no simulation. Each hop learns only where to forward next; only the exit sees the message, and no single hop sees both who you are and what you said.</p>
    <div class="vl-grid">
      <div class="vl-card">
        <h2>Compose</h2>
        <div class="vl-field">
          <label for="vlMsg">Message</label>
          <textarea id="vlMsg" placeholder="Type a secret to route…" spellcheck="false"></textarea>
          <small class="vl-hint">Padded into a fixed ${CELL}-byte cell so its length is hidden on the wire.</small>
        </div>
        <div class="vl-row">
          <div class="vl-field">
            <label for="vlHops">Relays (hops)</label>
            <select id="vlHops"><option>2</option><option selected>3</option><option>4</option><option>5</option></select>
            <small class="vl-hint">Each hop is a fresh ECDH key pair; more hops spread trust wider.</small>
          </div>
        </div>
        <div class="vl-acts">
          <button class="vl-btn pri" id="vlBuild">Build onion</button>
          <button class="vl-btn" id="vlPeel" disabled>Peel through relays</button>
        </div>
        <div class="vl-acts" style="margin-top:9px">
          <button class="vl-btn" id="vlReplay" disabled>Replay this onion</button>
          <button class="vl-btn" id="vlReset" disabled>Reset relays</button>
        </div>
        <div class="vl-note">A relay rejects an onion whose ephemeral key it has already seen — that is the replay defence. "Replay this onion" re-sends the exact same cell so you can watch the first hop refuse it.</div>
      </div>
      <div class="vl-card">
        <h2>Circuit</h2>
        <div class="vl-kpis" id="vlKpis"></div>
        <div class="vl-relays" id="vlRelays"></div>
        <div id="vlOnionWrap" style="margin-top:14px"></div>
        <h2 style="margin-top:18px">Peeling</h2>
        <div id="vlSteps"><div class="vl-empty">Build an onion, then peel it to watch each relay decrypt exactly one layer.</div></div>
        <div id="vlKnow"></div>
      </div>
    </div>`;

  const $ = (s) => main.querySelector(s);
  let relays = [], onion = null, cell = 0;

  const buildBtn = $("#vlBuild"), peelBtn = $("#vlPeel"), replayBtn = $("#vlReplay"), resetBtn = $("#vlReset");

  function paintKpis() {
    $("#vlKpis").innerHTML = `
      <div class="vl-kpi"><b>${relays.length || "—"}</b><span>Relays</span></div>
      <div class="vl-kpi"><b>${onion ? onion.length + " B" : "—"}</b><span>Onion size</span></div>
      <div class="vl-kpi"><b>${cell ? cell + " B" : "—"}</b><span>Payload cell</span></div>
      <div class="vl-kpi"><b>${relays.length ? relays.length : "—"}</b><span>AES-GCM layers</span></div>`;
  }
  function paintRelays() {
    $("#vlRelays").innerHTML = relays.length ? relays.map((r, i) => `
      <div class="vl-relay${i === relays.length - 1 ? " exit" : ""}">
        <span class="n">${i === relays.length - 1 ? "EX" : "R" + (i + 1)}</span>
        <div class="m"><b>${esc(r.name)}${i === relays.length - 1 ? " · exit" : ""}</b><code>pub ${esc(short(hex(r.pubRaw), 12))}</code></div>
      </div>`).join("") : `<div class="vl-empty">No circuit yet.</div>`;
  }

  async function doBuild() {
    buildBtn.disabled = true;
    const msg = $("#vlMsg").value || "";
    const n = parseInt($("#vlHops").value, 10) || 3;
    relays = [];
    for (let i = 0; i < n; i++) { const k = await genKey(); relays.push({ ...k, name: i === n - 1 ? "Exit gateway" : "Relay " + (i + 1), seen: new Set() }); }
    const built = await buildOnion(msg, relays);
    onion = built.onion; cell = built.cell;
    paintKpis(); paintRelays();
    const u = unpackPacket(onion);
    $("#vlOnionWrap").innerHTML = `<div class="vl-onion"><span class="lbl">onion cell → Relay 1</span><br>eph=${esc(short(hex(u.eph), 12))}<br>iv=${esc(hex(u.iv))}<br>ct[${u.ct.length}B]=${esc(short(hex(u.ct), 16))}</div>`;
    $("#vlSteps").innerHTML = `<div class="vl-empty">Onion built with ${relays.length} real AES-256-GCM layers. Peel it to decrypt hop by hop.</div>`;
    $("#vlKnow").innerHTML = "";
    peelBtn.disabled = false; replayBtn.disabled = true; resetBtn.disabled = false; buildBtn.disabled = false;
    toast(relays.length + "-hop onion built");
  }

  async function doPeel() {
    if (!onion) return;
    peelBtn.disabled = true;
    const { steps, recovered, failed } = await peelOnion(onion, relays);
    renderSteps(steps, recovered);
    if (!failed && recovered != null) renderKnows(relays); else $("#vlKnow").innerHTML = "";
    replayBtn.disabled = false; peelBtn.disabled = false;
    if (failed) toast("Peel stopped — see the log"); else toast("Message recovered at the exit");
  }

  function renderSteps(steps, recovered) {
    const box = $("#vlSteps");
    box.innerHTML = steps.map((st) => {
      if (st.replay) return `<div class="vl-step bad"><div class="sh"><span class="hp">Relay ${st.hop + 1}</span><span class="tag bad">Replay rejected</span></div><div class="sl">This relay has already processed the onion with ephemeral key <code>${esc(short(st.ephHex, 8))}</code>. It refuses to decrypt it again — replayed traffic is dropped.</div></div>`;
      if (st.error) return `<div class="vl-step bad"><div class="sh"><span class="hp">Relay ${st.hop + 1}</span><span class="tag bad">Decrypt failed</span></div><div class="sl">AES-GCM authentication failed — the layer was tampered with or malformed.</div></div>`;
      const who = st.exit ? "Exit gateway" : "Relay " + (st.hop + 1);
      const learns = st.exit
        ? `Derives the hop key via ECDH, decrypts the final layer and reads the message. It sees <b>what</b> was said, but received the cell from the previous relay — never from you.`
        : `Derives the hop key via ECDH with ephemeral <code>${esc(short(st.ephHex, 8))}</code>, decrypts one layer, and learns only to forward to <code>${esc(st.next)}</code>. The inner bytes stay encrypted.`;
      return `<div class="vl-step${st.exit ? " exit" : ""}"><div class="sh"><span class="hp">${esc(who)}</span><span class="tag${st.exit ? " ok" : ""}">${st.exit ? "Message recovered" : "Layer peeled"}</span></div><div class="sl">${learns}</div>${st.exit && recovered != null ? `<div class="msg">${esc(recovered)}</div>` : ""}</div>`;
    }).join("");
    // reveal in sequence
    [...box.querySelectorAll(".vl-step")].forEach((el, i) => setTimeout(() => el.classList.add("in"), 70 + i * 160));
  }

  function renderKnows(relays) {
    const rows = relays.map((r, i) => {
      const first = i === 0, exit = i === relays.length - 1;
      return `<tr><td>${esc(r.name)}</td><td class="${first ? "y" : "n"}">${first ? "Yes" : "No"}</td><td class="${exit ? "y" : "n"}">${exit ? "Yes" : "No"}</td><td class="n">No</td></tr>`;
    }).join("");
    $("#vlKnow").innerHTML = `
      <div class="vl-note" style="border-top:0;padding-top:16px"><b>What each hop knows</b></div>
      <table class="vl-know"><thead><tr><th>Hop</th><th>Knows the sender</th><th>Reads the message</th><th>Knows sender + message</th></tr></thead><tbody>${rows}</tbody></table>
      <div class="vl-note">No single relay learns both the sender and the message — that is the unlinkability onion routing buys. A production network also needs a large, diverse relay set and traffic-analysis defences (mixing, cover traffic); those are on Veil's roadmap, not in this module.</div>`;
  }

  function doReset() { relays.forEach((r) => r.seen = new Set()); toast("Relay replay caches cleared"); }

  buildBtn.onclick = doBuild;
  peelBtn.onclick = doPeel;
  replayBtn.onclick = doPeel;
  resetBtn.onclick = doReset;
  paintKpis(); paintRelays();
}

// ---- tab shell -------------------------------------------------------------
const TABS = [["onion", "Onion Lab"], ["search", "Dark-Web Search"], ["proxy", "Proxy Browser"]];

function renderLab(main, active) {
  const tab = active || "onion";
  main.innerHTML = `
  <div class="vl">
    <div class="vl-hero">
      <div>
        <h1>Veil — privacy lab</h1>
        <p>Real onion cryptography, real dark-web search, and a real server-side proxy browser — no simulation. Veil is a research prototype, not Tor: it does not anonymize your traffic and cannot open .onion sites for you.</p>
        <div class="vl-badges">
          <span class="vl-badge ok">Real crypto</span>
          <span class="vl-badge">Ahmia .onion index</span>
          <span class="vl-badge">Edge fetch proxy</span>
        </div>
      </div>
    </div>
    <div class="vl-tabs">${TABS.map(([id, label]) => `<button class="vl-tab${id === tab ? " on" : ""}" data-tab="${id}">${esc(label)}</button>`).join("")}</div>
    <div id="vlPanel"></div>
  </div>`;
  const panel = main.querySelector("#vlPanel");
  ({ onion: renderOnionLab, search: renderSearch, proxy: renderProxy }[tab] || renderOnionLab)(panel);
  main.querySelectorAll(".vl-tab").forEach((b) => { b.onclick = () => renderLab(main, b.dataset.tab); });
}

// ---- dark-web search (real, via Ahmia through the edge proxy) ---------------
function parseAhmia(html) {
  const out = [];
  let doc; try { doc = new DOMParser().parseFromString(String(html || ""), "text/html"); } catch (_) { return out; }
  doc.querySelectorAll("li.result").forEach((li) => {
    const a = li.querySelector("h4 a") || li.querySelector("a");
    const cite = li.querySelector("cite");
    // Prefer the canonical full URL from the result link's redirect_url; fall
    // back to the cite host (prefixing the scheme so it's openable in Tor).
    let onion = "";
    if (a) { const m = (a.getAttribute("href") || "").match(/redirect_url=([^&]+)/); if (m) { try { onion = decodeURIComponent(m[1]); } catch (_) { onion = m[1]; } } }
    if (!onion && cite) { onion = cite.textContent.trim(); if (onion && !/^https?:/i.test(onion)) onion = "http://" + onion; }
    const title = ((a ? a.textContent : "") || "").replace(/\s+/g, " ").trim() || onion || "Untitled";
    const p = li.querySelector("p");
    const desc = p ? p.textContent.replace(/\s+/g, " ").trim() : "";
    if (onion && /\.onion/i.test(onion)) out.push({ title, onion, desc });
  });
  return out;
}
// Real Ahmia search: step 1 reads the form's per-load hidden token from the home
// page (Ahmia 302s /search to / without it); step 2 submits q + that token.
async function ahmiaSearchOnce(term) {
  const home = await dnFetch("https://ahmia.fi/", { raw: true, timeout: 20000, ua: BROWSER_UA });
  let tokenPair = "";
  try {
    const hd = new DOMParser().parseFromString(home.body || "", "text/html");
    const hidden = hd.querySelector("#searchForm input[type=hidden]") || hd.querySelector("form input[type=hidden]");
    if (hidden && hidden.getAttribute("name")) tokenPair = "&" + encodeURIComponent(hidden.getAttribute("name")) + "=" + encodeURIComponent(hidden.getAttribute("value") || "");
  } catch (_) {}
  const r = await dnFetch("https://ahmia.fi/search/?q=" + encodeURIComponent(term) + tokenPair, { raw: true, timeout: 20000, ua: BROWSER_UA });
  return parseAhmia(r.body);
}
async function ahmiaSearch(term) {
  // Ahmia occasionally rate-limits the rapid home+search pair and deflects to its
  // home page (zero results); one retry after a short pause clears that blip.
  let hits = await ahmiaSearchOnce(term);
  if (!hits.length) { await new Promise((r) => setTimeout(r, 450)); hits = await ahmiaSearchOnce(term); }
  return hits;
}
function hitHTML(h) {
  return `<div class="vl-hit"><h3>${esc(h.title)}</h3><div class="on"><code>${esc(h.onion)}</code><button class="vl-btn vl-copy" data-copy="${esc(h.onion)}">Copy</button></div>${h.desc ? `<p>${esc(h.desc)}</p>` : ""}</div>`;
}
function wireCopy(scope) {
  scope.querySelectorAll(".vl-copy").forEach((b) => { b.onclick = async () => {
    try { await navigator.clipboard.writeText(b.dataset.copy || ""); } catch (_) {}
    const t = b.textContent; b.textContent = "Copied"; toast("Onion address copied"); setTimeout(() => { b.textContent = t; }, 1100);
  }; });
}
function renderSearch(main) {
  const ok = proxyConfigured();
  main.innerHTML = `
    <div class="vl-banner">Results come from <b>Ahmia</b> (ahmia.fi), a clearnet search engine that indexes Tor hidden services. The query runs server-side through the Darknode edge proxy — your browser never touches Tor. Darknode <b>cannot open .onion links for you</b>; copy an address and open it in <b>Tor Browser</b>. Ahmia filters known abuse material from its index; use this for lawful research only.</div>
    <div class="vl-bar">
      <div class="vl-field">
        <label for="vlQ">Search Tor hidden services</label>
        <input id="vlQ" type="text" placeholder="e.g. security forum" spellcheck="false" autocomplete="off">
        <small class="vl-hint">Searches .onion sites indexed by Ahmia. Press Enter or Search.</small>
      </div>
      <button class="vl-btn pri" id="vlGo" style="margin-top:22px"${ok ? "" : " disabled"}>Search</button>
    </div>
    <div id="vlSout">${ok ? `<div class="vl-empty">Enter a query to search indexed .onion services.</div>` : `<div class="vl-err">Live search is unavailable — the Darknode proxy is not configured in this build.</div>`}</div>`;
  if (!ok) return;
  const q = main.querySelector("#vlQ"), go = main.querySelector("#vlGo"), out = main.querySelector("#vlSout");
  async function run() {
    const term = (q.value || "").trim();
    if (!term) { out.innerHTML = `<div class="vl-empty">Type something to search.</div>`; return; }
    go.disabled = true; out.innerHTML = `<div class="vl-empty"><span class="vl-spin"></span>Searching Ahmia…</div>`;
    try {
      const hits = await ahmiaSearch(term);
      if (!hits.length) { out.innerHTML = `<div class="vl-empty">No results for <b>${esc(term)}</b> — Ahmia returned nothing, or blocked the proxied request. Try a broader term.</div>`; go.disabled = false; return; }
      out.innerHTML = `<div class="vl-meta"><span class="vl-pill ok">${hits.length} result${hits.length === 1 ? "" : "s"}</span><span class="vl-pill">source: ahmia.fi</span></div><div class="vl-res">${hits.map(hitHTML).join("")}</div>`;
      wireCopy(out);
    } catch (e) { out.innerHTML = `<div class="vl-err">Search failed: ${esc((e && e.message) || String(e))}</div>`; }
    go.disabled = false;
  }
  go.onclick = run;
  q.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } });
  q.focus();
}

// ---- proxy browser (real server-side fetch via the edge proxy) -------------
function renderProxy(main) {
  const ok = proxyConfigured();
  main.innerHTML = `
    <div class="vl-banner">Veil fetches the page <b>server-side</b> through the Darknode edge proxy and shows it read-only. The target site sees the proxy, not your browser — but this is <b>not anonymity</b> (no Tor), and scripts are disabled in the preview. <b>.onion addresses will not load</b> (the edge cannot resolve Tor) — use Tor Browser for those.</div>
    <div class="vl-bar">
      <div class="vl-field">
        <label for="vlU">Fetch a web page</label>
        <input id="vlU" type="text" placeholder="https://example.com" spellcheck="false" autocomplete="off">
        <small class="vl-hint">Public http/https sites only. Private and reserved hosts are blocked.</small>
      </div>
      <button class="vl-btn pri" id="vlFetch" style="margin-top:22px"${ok ? "" : " disabled"}>Fetch</button>
    </div>
    <label class="vl-note" style="border-top:0;margin-top:4px;padding-top:0;display:flex;align-items:center;gap:7px;cursor:pointer;color:#38435c"><input type="checkbox" id="vlSrc"> View raw source instead of the rendered page</label>
    <div id="vlPout">${ok ? `<div class="vl-empty">Enter a URL to fetch it through the proxy.</div>` : `<div class="vl-err">The proxy browser is unavailable — the Darknode proxy is not configured in this build.</div>`}</div>`;
  if (!ok) return;
  const u = main.querySelector("#vlU"), go = main.querySelector("#vlFetch"), out = main.querySelector("#vlPout"), srcChk = main.querySelector("#vlSrc");
  let last = null; // cached last response, so the raw/rendered toggle re-paints without re-fetching

  function paint() {
    if (!last) return;
    const r = last;
    const good = r.status >= 200 && r.status < 400;
    const ct = r.contentType || "";
    const meta = `<div class="vl-meta"><span class="vl-pill ${good ? "ok" : "bad"}">HTTP ${r.status}${r.statusText ? " " + esc(r.statusText) : ""}</span><span class="vl-pill">${esc((ct.split(";")[0]) || "unknown")}</span>${r.bytes != null ? `<span class="vl-pill">${Number(r.bytes).toLocaleString()} B${r.truncated ? " · truncated" : ""}</span>` : ""}${r.finalUrl && r.finalUrl !== r.url ? `<span class="vl-pill">→ ${esc(r.finalUrl)}</span>` : ""}</div>`;
    const isHtml = /html/.test(ct) || /^\s*(<!doctype html|<html)/i.test(r.body || "");
    if (srcChk.checked || !isHtml) {
      out.innerHTML = meta + `<pre class="vl-src">${esc((r.body || "").slice(0, 100000))}</pre>`;
    } else {
      const base = r.finalUrl || r.url;
      let docHtml = String(r.body || "");
      const baseTag = `<base href="${esc(base)}">`;
      docHtml = /<head[^>]*>/i.test(docHtml) ? docHtml.replace(/<head[^>]*>/i, (m) => m + baseTag) : baseTag + docHtml;
      out.innerHTML = meta + `<iframe class="vl-frame" sandbox="" referrerpolicy="no-referrer"></iframe>`;
      const fr = out.querySelector("iframe");
      try { fr.srcdoc = docHtml; } catch (_) { out.innerHTML = meta + `<pre class="vl-src">${esc(docHtml.slice(0, 100000))}</pre>`; }
    }
  }

  async function run() {
    let url = (u.value || "").trim();
    if (!url) { out.innerHTML = `<div class="vl-empty">Type a URL to fetch.</div>`; return; }
    if (!/^https?:\/\//i.test(url)) url = "https://" + url;
    go.disabled = true; last = null; out.innerHTML = `<div class="vl-empty"><span class="vl-spin"></span>Fetching ${esc(url)}…</div>`;
    try {
      const r = await dnFetch(url, { raw: true, timeout: 20000, ua: BROWSER_UA });
      last = { url, finalUrl: r.finalUrl, status: r.status, statusText: r.statusText, contentType: r.contentType, body: r.body, bytes: r.bytes, truncated: r.truncated };
      paint();
    } catch (e) { out.innerHTML = `<div class="vl-err">Fetch failed: ${esc((e && e.message) || String(e))}</div>`; }
    go.disabled = false;
  }
  go.onclick = run;
  u.addEventListener("keydown", (e) => { if (e.key === "Enter") { e.preventDefault(); run(); } });
  srcChk.addEventListener("change", () => { if (last) paint(); });
  u.focus();
}
