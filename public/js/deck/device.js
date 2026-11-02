// "This Computer" scene (desktop app only). Shows what the app can do on this machine
// that a browser cannot: a workstation hardening audit, direct DNS / WHOIS / TLS lookups
// (no proxy), installed local AI models, and the native tools. Every call goes through the
// app's read-only device bridge (window.darknode.native); the main process checks each one.
const S = { ctx: null, el: null, audit: null, busy: {} };
const E = (s) => (S.ctx && S.ctx.esc ? S.ctx.esc(s) : String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])));
const N = () => (window.darknode && window.darknode.native) || null;

const TOOLS = [
  ["runner", "Terminal", "Real shells on this computer, in tabs."],
  ["scanner", "Port Scanner", "Native TCP scan with banner grabbing, scope-gated."],
  ["fuzzer", "Web Fuzzer", "Directory and file discovery against your own sites."],
  ["recon", "Recon", "Subdomains, DNS and service discovery."],
  ["vms", "Virtual Machines", "Run and control QEMU virtual machines."],
  ["forensics", "File Forensics", "Hashes, entropy, strings and file type from the real bytes."],
  ["loot", "Saved Output", "Everything your runs saved to disk."],
  ["home", "All Native Tools", "The full native tools window."],
];

function injectStyle() {
  if (document.getElementById("dv-css")) return;
  const st = document.createElement("style"); st.id = "dv-css";
  st.textContent = `
.dv-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}
@media (max-width:1100px){.dv-grid{grid-template-columns:minmax(0,1fr)}}
.dv-card{border:1px solid rgba(23,33,56,.12);border-radius:10px;padding:16px 18px;background:#fff;min-width:0}
.dv-card.wide{grid-column:1/-1}
.dv-card h2{font-size:15px;font-weight:600;margin:0 0 4px}
.dv-sub{color:#5a6680;font-size:12.5px;line-height:1.5;margin:0 0 12px}
.dv-kv{display:grid;grid-template-columns:140px minmax(0,1fr);gap:6px 12px;font-size:13px}
.dv-kv dt{color:#5a6680}.dv-kv dd{margin:0;overflow-wrap:anywhere}
.dv-btn{appearance:none;border:1px solid rgba(23,33,56,.18);background:#fff;border-radius:7px;font:inherit;font-size:12.5px;font-weight:600;color:#2a3450;padding:6px 12px;cursor:pointer}
.dv-btn:hover{border-color:var(--dk-acc,#2552c6);color:var(--dk-acc,#2552c6)}
.dv-btn.pri{background:#141c2e;border-color:#141c2e;color:#fff}
.dv-btn[disabled]{opacity:.55;cursor:default}
.dv-row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}
.dv-in{flex:1;min-width:200px;font:inherit;font-size:13px;border:1px solid rgba(23,33,56,.2);border-radius:7px;padding:7px 10px}
.dv-out{margin:12px 0 0;font-size:12.5px}
.dv-pre{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;line-height:1.55;background:rgba(23,33,56,.04);border:1px solid rgba(23,33,56,.08);border-radius:8px;padding:10px 12px;max-height:320px;overflow:auto;white-space:pre-wrap;overflow-wrap:anywhere;margin:0}
.dv-score{display:flex;align-items:baseline;gap:12px;margin:12px 0 8px}
.dv-grade{font-size:30px;font-weight:700;line-height:1}
.dv-counts{color:#5a6680;font-size:12.5px}
.dv-item{border-top:1px solid rgba(23,33,56,.08);padding:9px 0;font-size:13px}
.dv-item b{font-weight:600}
.dv-st{display:inline-block;min-width:44px;font-size:11px;font-weight:700;margin-right:8px}
.dv-st.fail{color:#c62828}.dv-st.warn{color:#9a5b00}.dv-st.pass{color:#137a45}.dv-st.na,.dv-st.error{color:#5a6680}
.dv-ev{color:#5a6680;font-size:12px;margin:3px 0 0 52px;overflow-wrap:anywhere}
.dv-fix{font-size:12px;margin:3px 0 0 52px}
.dv-tools{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:10px}
.dv-tool{appearance:none;text-align:left;border:1px solid rgba(23,33,56,.12);border-radius:9px;background:#fff;padding:11px 13px;cursor:pointer;font:inherit}
.dv-tool:hover{border-color:var(--dk-acc,#2552c6)}
.dv-tool b{display:block;font-size:13px;margin:0 0 3px}.dv-tool span{color:#5a6680;font-size:12px;line-height:1.45}
.dv-models{display:flex;flex-direction:column;gap:0}
.dv-model{display:flex;justify-content:space-between;gap:10px;border-top:1px solid rgba(23,33,56,.08);padding:7px 0;font-size:13px}
.dv-model span{color:#5a6680;font-size:12px}
.dv-note{color:#5a6680;font-size:12.5px;line-height:1.5}
`;
  document.head.appendChild(st);
}

const gb = (n) => (n >= 1e9 ? (n / 1e9).toFixed(1) + " GB" : n >= 1e6 ? Math.round(n / 1e6) + " MB" : n ? n + " B" : "");

export function mountDevice(el, ctx) {
  injectStyle();
  S.ctx = ctx || S.ctx; S.el = el;
  const nat = N();
  if (!nat || typeof nat.sysinfo !== "function") {
    el.innerHTML = `<div class="dk-ovhead"><div><h1>This Computer</h1><p>Available in the Darknode desktop app.</p></div></div>`;
    return;
  }
  el.innerHTML = `
    <div class="dk-ovhead"><div><h1>This Computer</h1><p>What the desktop app does on this machine that a browser cannot. Checks, lookups and models on this page run locally.</p></div></div>
    <div class="dv-grid">
      <section class="dv-card"><h2>Device</h2><p class="dv-sub">Read from the operating system.</p><dl class="dv-kv" id="dvSys"><dt>Loading</dt><dd></dd></dl></section>
      <section class="dv-card"><h2>Local AI models</h2><p class="dv-sub">Models installed in Ollama on this computer. Prompts to them never leave the machine.</p><div id="dvModels" class="dv-note">Checking…</div></section>
      <section class="dv-card wide"><h2>Workstation hardening audit</h2><p class="dv-sub">Real checks against this computer's settings (disk encryption, firewall, updates, screen lock, SSH, listening services and more), mapped to CIS benchmarks.</p>
        <div class="dv-row"><button class="dv-btn pri" id="dvAudit">Run audit</button><button class="dv-btn" id="dvAuditAsk" hidden>Ask the Assistant how to fix these</button></div>
        <div id="dvAuditOut"></div></section>
      <section class="dv-card wide"><h2>Network lookups</h2><p class="dv-sub">Direct from this computer: the system resolver for DNS, WHOIS over port 43 and a live TLS handshake, with no relay in between. TLS needs the host authorized in the native tools' scope.</p>
        <div class="dv-row"><input class="dv-in" id="dvHost" placeholder="Domain or host" autocomplete="off" spellcheck="false"><button class="dv-btn" data-lk="dns">DNS records</button><button class="dv-btn" data-lk="whois">WHOIS</button><button class="dv-btn" data-lk="tls">TLS certificate</button></div>
        <div class="dv-out" id="dvLookOut"></div></section>
      <section class="dv-card wide"><h2>Native tools</h2><p class="dv-sub">Open in their own window, with full access to this computer.</p>
        <div class="dv-tools">${TOOLS.map(([id, name, d]) => `<button class="dv-tool" data-nt="${id}"><b>${E(name)}</b><span>${E(d)}</span></button>`).join("")}</div></section>
    </div>`;

  nat.sysinfo().then((s) => {
    const box = el.querySelector("#dvSys"); if (!box || !s) return;
    const rows = [["Host", s.hostname], ["System", [s.platform, s.release, s.arch].filter(Boolean).join(" ")], ["Processor cores", s.cpus], ["Memory", s.mem], ["Desktop app", s.version ? "v" + s.version : ""]];
    box.innerHTML = rows.filter((r) => r[1] !== undefined && r[1] !== "").map(([k, v]) => `<dt>${E(k)}</dt><dd>${E(v)}</dd>`).join("");
  }, () => {});

  (nat.models ? nat.models() : Promise.resolve(null)).then((r) => {
    const box = el.querySelector("#dvModels"); if (!box) return;
    if (!r || !r.ok) { box.innerHTML = `${E((r && r.error) || "Ollama is not running on this computer")}. Install it from ollama.com and pull a model to run AI fully offline.`; return; }
    if (!r.models.length) { box.textContent = "Ollama is running but has no models yet. Pull one with: ollama pull llama3.2"; return; }
    box.className = "dv-models";
    box.innerHTML = r.models.map((m) => `<div class="dv-model"><b>${E(m.name)}</b><span>${E([m.params, m.family, gb(m.size)].filter(Boolean).join(" · "))}</span></div>`).join("");
  }, () => {});

  el.querySelector("#dvAudit").onclick = runAudit;
  el.querySelector("#dvAuditAsk").onclick = () => {
    const bad = ((S.audit && S.audit.results) || []).filter((r) => r.status === "fail" || r.status === "warn");
    if (!bad.length || !S.ctx.askAI) return;
    S.ctx.askAI("My workstation hardening audit (" + (S.audit.os || S.audit.platform) + ") found these issues. Give me the exact steps to fix each one, most important first:\n" + bad.map((r) => "- [" + r.status + ", " + r.severity + "] " + r.title + ": " + String(r.evidence || "").slice(0, 200)).join("\n"));
  };
  el.querySelectorAll("[data-lk]").forEach((b) => { b.onclick = () => lookup(b.dataset.lk); });
  el.querySelector("#dvHost").onkeydown = (e) => { if (e.key === "Enter") lookup("dns"); };
  el.querySelectorAll("[data-nt]").forEach((b) => { b.onclick = () => { try { nat.open(b.dataset.nt); } catch (_) {} }; });
}

const ORDER = { fail: 0, warn: 1, error: 2, pass: 3, na: 4 };
const ST_LABEL = { fail: "FAIL", warn: "WARN", pass: "PASS", na: "N/A", error: "ERROR" };

async function runAudit() {
  const el = S.el, nat = N(); if (!el || !nat || S.busy.audit) return;
  const btn = el.querySelector("#dvAudit"), out = el.querySelector("#dvAuditOut");
  S.busy.audit = true; btn.disabled = true; btn.textContent = "Running checks…";
  out.innerHTML = `<p class="dv-note" style="margin-top:12px">Checking this computer. This takes a few seconds.</p>`;
  let r; try { r = await nat.audit(); } catch (e) { r = { ok: false, error: e && e.message }; }
  S.busy.audit = false; btn.disabled = false; btn.textContent = "Run again";
  if (!r || !r.ok) { out.innerHTML = `<p class="dv-note" style="margin-top:12px">The audit could not run: ${E((r && r.error) || "unknown error")}</p>`; return; }
  const rep = S.audit = r.report, sc = rep.score || {}, c = sc.counts || {};
  const items = rep.results.slice().sort((a, b) => (ORDER[a.status] ?? 9) - (ORDER[b.status] ?? 9));
  out.innerHTML = `
    <div class="dv-score"><span class="dv-grade">${E(sc.grade || "n/a")}</span><span>${sc.percent != null ? E(sc.percent) + "%" : ""}</span><span class="dv-counts">${E(c.pass || 0)} passed · ${E(c.fail || 0)} failed · ${E(c.warn || 0)} warnings · ${E((c.na || 0) + (c.error || 0))} not applicable or not checked</span></div>
    ${items.map((x) => `<div class="dv-item"><span class="dv-st ${E(x.status)}">${E(ST_LABEL[x.status] || x.status)}</span><b>${E(x.title)}</b> <span class="dv-counts">${E(x.cisRef || "")}</span>
      ${x.evidence ? `<div class="dv-ev">${E(String(x.evidence).slice(0, 300))}</div>` : ""}
      ${x.fix && (x.status === "fail" || x.status === "warn") ? `<div class="dv-fix">${E(x.fix)}</div>` : ""}</div>`).join("")}`;
  el.querySelector("#dvAuditAsk").hidden = !((c.fail || 0) + (c.warn || 0)) || !S.ctx.askAI;
}

async function lookup(kind) {
  const el = S.el, nat = N(); if (!el || !nat) return;
  const host = el.querySelector("#dvHost").value.trim().replace(/^https?:\/\//i, "").split("/")[0];
  const out = el.querySelector("#dvLookOut");
  if (!host) { out.innerHTML = `<p class="dv-note">Enter a domain or host first.</p>`; el.querySelector("#dvHost").focus(); return; }
  if (S.busy.look) return;
  S.busy.look = true; out.innerHTML = `<p class="dv-note">Looking up ${E(host)}…</p>`;
  let r; try { r = kind === "dns" ? await nat.dns(host) : kind === "whois" ? await nat.whois(host) : await nat.tls(host, 443); } catch (e) { r = { ok: false, error: e && e.message }; }
  S.busy.look = false;
  if (!r || !r.ok) {
    out.innerHTML = r && r.blocked
      ? `<p class="dv-note">${E(host)} is not authorized for TLS checks yet (${E(r.error || "out of scope")}). Authorize it in the native tools, then try again.</p><div class="dv-row"><button class="dv-btn" id="dvScope">Open Engagement scope</button></div>`
      : `<p class="dv-note">Lookup failed: ${E((r && r.error) || "unknown error")}</p>`;
    const sb = out.querySelector("#dvScope"); if (sb) sb.onclick = () => { try { nat.open("engagement"); } catch (_) {} };
    return;
  }
  if (kind === "whois") { out.innerHTML = `<pre class="dv-pre">${E(r.text || "")}</pre>`; return; }
  if (kind === "tls") {
    const c = r.cert || {};
    const rows = [["Subject", c.subject], ["Issuer", c.issuer], ["Valid from", c.valid_from], ["Valid to", c.valid_to], ["Days left", c.daysLeft], ["Names", c.san], ["Protocol", c.protocol], ["Cipher", c.cipher], ["Key size", c.bits], ["SHA-256", c.fingerprint256]];
    out.innerHTML = `<dl class="dv-kv">${rows.filter((x) => x[1] !== undefined && x[1] !== null && x[1] !== "").map(([k, v]) => `<dt>${E(k)}</dt><dd>${E(v)}</dd>`).join("")}</dl>`;
    return;
  }
  const rec = r.rec || {};
  const fmt = (v) => (Array.isArray(v) ? v.map((x) => (typeof x === "string" ? x : Array.isArray(x) ? x.join("") : JSON.stringify(x))).join("\n") : typeof v === "object" ? JSON.stringify(v) : String(v));
  const keys = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "DMARC_TXT"].filter((k) => rec[k] && (!Array.isArray(rec[k]) || rec[k].length));
  out.innerHTML = keys.length
    ? `<dl class="dv-kv">${keys.map((k) => `<dt>${E(k === "DMARC_TXT" ? "DMARC" : k)}</dt><dd><pre class="dv-pre" style="max-height:140px">${E(fmt(rec[k]))}</pre></dd>`).join("")}</dl>`
    : `<p class="dv-note">No records found for ${E(host)}.</p>`;
}
