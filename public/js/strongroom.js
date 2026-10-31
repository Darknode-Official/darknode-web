// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
//
// STRONGROOM — Fund Protection (v1 bridgehead UI).
//
// A client-side command center for the cyber-financial FUSION engine
// (docs/plans/STRONGROOM-FUSION-ENGINE.md). You load your OWN ledger / payments export and,
// optionally, a feed of access & identity events; the deterministic engine screens the
// money for fraud schemes and, when both feeds are present, correlates them to surface the
// intrusion -> fund-theft kill chain that single-plane tools miss.
//
// Nothing is uploaded — all analysis runs in your browser. Nothing is simulated: the
// engine analyses exactly the rows you provide. Findings are screens and leads for review,
// not an audit and not proof of wrongdoing (see the disclaimer banner).
//
//   renderStrongroom(main) -> void

import { analyze, selfTest } from "/js/strongroom/engine.js?v=20261029c";
import { attachSinkButton } from "./core/sink.js";
import { fusionFindings } from "/js/strongroom/strongroom-sink.js";

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const toast = (m) => { try { (window.dnToast || window.showToast || (() => {}))(m); } catch (_) {} };
const fmtMoney = (n) => (isFinite(n) ? "$" + Number(n).toLocaleString(undefined, { maximumFractionDigits: 2 }) : "—");

const SEV_META = {
  critical: { label: "Critical", c: "#b00020" },
  high: { label: "High", c: "#d9480f" },
  medium: { label: "Medium", c: "#b58100" },
  low: { label: "Low", c: "#2b6cb0" },
  info: { label: "Info", c: "#667085" },
};
const SOUND_HELP = {
  exact: "Exact match — deterministic, no interpretation.",
  precise: "Precise rule — a defined condition is or is not met.",
  heuristic: "Heuristic — a strong indicator that needs human confirmation.",
  screen: "Statistical screen — highlights items for review; never proof of fraud.",
};

// Clearly-labelled SYNTHETIC sample so a first-time user can see the engine work.
// It is fake and marked as such; real use is loading your own export.
const SAMPLE_PAY = [
  "date,vendor,amount,invoice,account,approver,initiator",
  "2026-01-05,Vendor A Supply,12480.00,INV-1001,DE89****,user01,user02",
  "2026-01-06,Vendor A Supply,12480.00,INV-1001,DE89****,user01,user02",
  "2026-01-08,Vendor B Logistics,9600.00,INV-2201,GB22****,user03,user03",
  "2026-01-09,Vendor B Logistics,9550.00,INV-2202,GB22****,user03,user03",
  "2026-01-11,Vendor B Logistics,9700.00,INV-2203,GB22****,user03,user03",
  "2026-01-14,Vendor C Partners,3000.00,INV-3310,FR14****,user04,user05",
  "2026-01-18,Vendor D Consulting,264000.00,INV-77,FR76****,user06,user07",
  "2026-01-24,Vendor E Foods,41000.00,INV-8800,NL55****,user01,user08",
].join("\n");
const SAMPLE_ACCESS = [
  "date,actor,type,vendor,detail",
  "2026-01-02,,vendor_bank_change,Vendor A Supply,beneficiary IBAN changed via emailed request",
  "2026-01-17,user06,login_new_geo,,sign-in from new ASN / country",
  "2026-01-17,user06,mfa_enrolled,,new authenticator device registered",
].join("\n");

const TEMPLATE_PAY = "date,vendor,amount,invoice,account,approver,initiator\n2026-01-15,Vendor name,12500.00,INV-0001,IBAN-or-acct,approver_user,initiator_user\n";
const TEMPLATE_ACCESS = "date,actor,type,vendor,detail\n2026-01-14,user01,vendor_bank_change,Vendor name,bank account updated\n# type values: vendor_bank_change, mailbox_rule_added, login_new_geo, impossible_travel, mfa_enrolled, oauth_grant, vendor_list_export, privilege_escalation\n";

function download(name, text) {
  const blob = new Blob([text], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name; document.body.appendChild(a); a.click();
  setTimeout(() => { a.remove(); URL.revokeObjectURL(url); }, 100);
}

function injectStyle() {
  if (document.getElementById("sr-style")) return;
  const s = document.createElement("style");
  s.id = "sr-style";
  s.textContent = `
  .sr{width:100%;padding:4px 2px 48px}
  .sr .sr-hd{display:flex;flex-wrap:wrap;align-items:flex-end;gap:12px;margin:8px 0 6px}
  .sr .sr-hd h1{font-size:1.5rem;margin:0;font-weight:800;letter-spacing:-.01em}
  .sr .sr-hd .sr-sub{color:var(--mut,#667085);font-size:.9rem;max-width:720px;line-height:1.5}
  .sr .sr-tag{display:inline-block;font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#2552c6;background:rgba(47,95,255,.12);padding:3px 9px;border-radius:999px}
  .sr .sr-warn{border:1px solid #f0c36d;background:rgba(240,195,109,.1);color:#7a5b00;border-radius:10px;padding:11px 14px;font-size:.84rem;line-height:1.5;margin:10px 0}
  .sr .sr-grid2{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,320px),1fr));gap:14px;margin:14px 0}
  .sr .sr-grid2>*{min-width:0}
  .sr .sr-card{border:1px solid var(--bd,#e3e8ef);border-radius:14px;background:var(--card,#fff);padding:15px 16px}
  .sr .sr-card h3{margin:0 0 3px;font-size:.98rem;font-weight:700}
  .sr .sr-card .sr-note{color:var(--mut,#667085);font-size:.8rem;line-height:1.45;margin:0 0 10px}
  .sr textarea{width:100%;box-sizing:border-box;min-height:120px;resize:vertical;font-family:ui-monospace,"JetBrains Mono",monospace;font-size:12px;line-height:1.5;border:1px solid var(--bd,#e3e8ef);border-radius:9px;padding:9px 10px;background:var(--bg2,#fafbfc);color:inherit}
  .sr .sr-row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-top:9px}
  .sr .sr-btn{appearance:none;font:inherit;font-size:.82rem;font-weight:600;border:1px solid var(--bd,#d7deea);background:var(--card,#fff);color:inherit;border-radius:8px;padding:7px 12px;cursor:pointer}
  .sr .sr-btn:hover{background:rgba(47,95,255,.06);border-color:#9db4ff}
  .sr .sr-btn.pri{background:#2552c6;border-color:#2552c6;color:#fff}
  .sr .sr-btn.pri:hover{background:#1c45ad}
  .sr .sr-file{font-size:.78rem;color:var(--mut,#667085)}
  .sr .sr-run{display:flex;flex-wrap:wrap;gap:10px;align-items:center;margin:4px 0 16px}
  .sr .sr-kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,150px),1fr));gap:10px;margin:14px 0}
  .sr .sr-kpi{border:1px solid var(--bd,#e3e8ef);border-radius:12px;padding:12px 14px;background:var(--card,#fff);min-width:0}
  .sr .sr-kpi .k{font-size:.72rem;text-transform:uppercase;letter-spacing:.05em;color:var(--mut,#8893a7);font-weight:600}
  .sr .sr-kpi .v{font-size:1.3rem;font-weight:800;margin-top:3px;overflow-wrap:anywhere}
  .sr .sr-sevbar{display:flex;flex-wrap:wrap;gap:7px;margin:4px 0 16px}
  .sr .sr-chip{font-size:.75rem;font-weight:700;border-radius:999px;padding:4px 11px;color:#fff}
  .sr .sr-find{border:1px solid var(--bd,#e3e8ef);border-left-width:4px;border-radius:11px;background:var(--card,#fff);padding:12px 14px;margin-bottom:10px}
  .sr .sr-find .ft{display:flex;flex-wrap:wrap;gap:8px;align-items:baseline}
  .sr .sr-find .ft .tt{font-weight:700;font-size:.95rem}
  .sr .sr-find .ft .mm{margin-left:auto;font-weight:800}
  .sr .sr-find .fmeta{font-size:.74rem;color:var(--mut,#8893a7);margin:2px 0 7px;display:flex;flex-wrap:wrap;gap:10px}
  .sr .sr-find .fwhy{font-size:.86rem;line-height:1.5;margin:0 0 7px}
  .sr .sr-find details summary{cursor:pointer;font-size:.8rem;color:#2552c6;font-weight:600}
  .sr .sr-find .fev{font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.6;color:var(--mut,#667085);margin:7px 0 0;white-space:pre-wrap;word-break:break-word}
  .sr .sr-legend{font-size:.78rem;color:var(--mut,#667085);line-height:1.7;margin-top:8px}
  .sr .sr-legend b{color:inherit}
  .sr .sr-empty{text-align:center;color:var(--mut,#8893a7);padding:34px 10px;font-size:.9rem}
  .sr .sr-selftest{font-size:.8rem;margin-top:6px}
  .sr .sr-selftest .ok{color:#1a7f37;font-weight:700}
  .sr .sr-selftest .bad{color:#b00020;font-weight:700}
  `;
  document.head.appendChild(s);
}

export function renderStrongroom(main) {
  injectStyle();
  main.innerHTML = `
  <div class="sr">
    <div class="sr-hd">
      <h1>STRONGROOM</h1><span class="sr-tag">Payment Fraud</span>
    </div>
    <div class="sr-sub">Load your own ledger or payments export and the engine screens it for fraud schemes.
      Add a feed of access &amp; identity events to correlate the two and surface the <b>intrusion&nbsp;&rarr;&nbsp;fund-theft</b>
      kill chain that email-only and ERP-only tools miss. Everything runs in your browser — nothing is uploaded.</div>

    <div class="sr-warn"><b>Leads, not verdicts.</b> These are deterministic screens and correlations to help you
      investigate. They are <b>not an audit</b>, <b>not accounting/legal/financial advice</b>, and <b>not a
      determination of fraud</b>. False positives and false negatives both happen; a quiet result is not proof your
      funds are safe. Verify every flagged item through your own controls and professionals.</div>

    <div class="sr-grid2">
      <div class="sr-card">
        <h3>1. Payments / ledger <span style="color:#b00020">(required)</span></h3>
        <p class="sr-note">Paste CSV or load a file. Columns are auto-detected: date, vendor/payee, amount, invoice/ref,
          account/IBAN, approver, initiator. Order doesn't matter.</p>
        <textarea id="srPay" placeholder="date,vendor,amount,invoice,account,approver,initiator"></textarea>
        <div class="sr-row">
          <label class="sr-btn">Load file<input type="file" id="srPayFile" accept=".csv,.txt,text/csv" hidden></label>
          <span class="sr-file" id="srPayName"></span>
          <button class="sr-btn" id="srPayTpl">Download template</button>
        </div>
      </div>
      <div class="sr-card">
        <h3>2. Access &amp; identity events <span style="color:var(--mut,#8893a7)">(optional — enables Fusion)</span></h3>
        <p class="sr-note">Columns: date, actor/user, type, vendor, detail. Recognised types include
          vendor_bank_change, mailbox_rule_added, login_new_geo, mfa_enrolled, oauth_grant, vendor_list_export.</p>
        <textarea id="srAcc" placeholder="date,actor,type,vendor,detail"></textarea>
        <div class="sr-row">
          <label class="sr-btn">Load file<input type="file" id="srAccFile" accept=".csv,.txt,text/csv" hidden></label>
          <span class="sr-file" id="srAccName"></span>
          <button class="sr-btn" id="srAccTpl">Download template</button>
        </div>
      </div>
    </div>

    <div class="sr-run">
      <button class="sr-btn pri" id="srRun">Run analysis</button>
      <button class="sr-btn" id="srSample">Load example (synthetic)</button>
      <button class="sr-btn" id="srClear">Clear</button>
      <button class="sr-btn" id="srTest">Run engine self-test</button>
      <span class="sr-selftest" id="srTestOut"></span>
    </div>

    <div id="srResults"></div>

    <div class="sr-card" style="margin-top:18px">
      <h3>How to read findings</h3>
      <div class="sr-legend">
        <b>Soundness</b> is shown on every finding: <b>exact</b> (deterministic match, e.g. identical duplicate payment) ·
        <b>precise</b> (a defined rule is met, e.g. same person initiated and approved) · <b>heuristic</b> (a strong
        indicator needing confirmation) · <b>screen</b> (a statistical lens such as Benford — a lens, never proof).<br>
        <b>Fusion chains</b> join an access/identity event to a payment on the same vendor or approver inside a time
        window. A single leg alone is low signal; a stitched chain to real money moving is the high-severity case.<br>
        <b>Money at risk</b> sums the amounts on medium-or-higher findings; treat it as exposure to review, not a loss total.
      </div>
    </div>
  </div>`;

  const $ = (id) => main.querySelector("#" + id);
  const payTA = $("srPay"), accTA = $("srAcc");
  let sampleLoaded = false;

  const readFile = (input, ta, nameEl) => {
    const f = input.files && input.files[0];
    if (!f) return;
    const fr = new FileReader();
    fr.onload = () => { ta.value = String(fr.result || ""); nameEl.textContent = f.name; sampleLoaded = false; };
    fr.onerror = () => toast("Could not read file");
    fr.readAsText(f);
  };
  $("srPayFile").addEventListener("change", (e) => readFile(e.target, payTA, $("srPayName")));
  $("srAccFile").addEventListener("change", (e) => readFile(e.target, accTA, $("srAccName")));
  $("srPayTpl").addEventListener("click", () => download("strongroom-payments-template.csv", TEMPLATE_PAY));
  $("srAccTpl").addEventListener("click", () => download("strongroom-access-events-template.csv", TEMPLATE_ACCESS));

  $("srSample").addEventListener("click", () => {
    payTA.value = SAMPLE_PAY; accTA.value = SAMPLE_ACCESS; sampleLoaded = true;
    $("srPayName").textContent = "example (synthetic)"; $("srAccName").textContent = "example (synthetic)";
    toast("Loaded synthetic example data");
  });
  $("srClear").addEventListener("click", () => {
    payTA.value = ""; accTA.value = ""; sampleLoaded = false;
    $("srPayName").textContent = ""; $("srAccName").textContent = ""; $("srResults").innerHTML = "";
  });
  $("srTest").addEventListener("click", () => {
    const { pass, results } = selfTest();
    const out = $("srTestOut");
    out.innerHTML = pass
      ? `<span class="ok">Self-test passed</span> — ${results.length}/${results.length} checks (engine deterministic &amp; correct).`
      : `<span class="bad">Self-test FAILED</span> — ${results.filter((r) => !r.pass).map((r) => esc(r.name)).join(", ")}`;
  });

  $("srRun").addEventListener("click", () => {
    const pay = payTA.value.trim();
    if (!pay) { toast("Add a payments/ledger CSV first"); return; }
    let res;
    try { res = analyze(pay, accTA.value.trim()); }
    catch (e) { $("srResults").innerHTML = `<div class="sr-warn">Analysis error: ${esc(e.message)}</div>`; return; }
    renderResults($("srResults"), res, sampleLoaded);
  });
}

function renderResults(host, res, sample) {
  const { findings, summary, warnings } = res;
  const kpi = (k, v) => `<div class="sr-kpi"><div class="k">${esc(k)}</div><div class="v">${v}</div></div>`;
  let html = "";
  if (sample) html += `<div class="sr-warn"><b>Showing EXAMPLE (synthetic) data.</b> These are fabricated rows to demonstrate the engine — not real records.</div>`;
  if (warnings && warnings.length) html += `<div class="sr-warn">${warnings.map(esc).join("<br>")}</div>`;

  html += `<div class="sr-kpis">
    ${kpi("Payments", summary.payments.toLocaleString())}
    ${kpi("Total value", fmtMoney(summary.totalValue))}
    ${kpi("Vendors", summary.vendors.toLocaleString())}
    ${kpi("Access events", summary.accessEvents.toLocaleString())}
    ${kpi("Fusion chains", summary.fusionChains.toLocaleString())}
    ${kpi("Money at risk", fmtMoney(summary.moneyAtRisk))}
  </div>`;

  const chips = Object.keys(SEV_META).filter((s) => summary.counts[s]).map((s) =>
    `<span class="sr-chip" style="background:${SEV_META[s].c}">${SEV_META[s].label}: ${summary.counts[s]}</span>`).join("");
  if (chips) html += `<div class="sr-sevbar">${chips}</div>`;
  if (summary.fusionChains) html += `<div class="sr-row" id="srSink" style="margin:-6px 0 14px"></div>`;

  if (summary.dateRange) html += `<div class="sr-file" style="margin:-6px 0 12px">Date range: ${esc(summary.dateRange[0])} to ${esc(summary.dateRange[1])}</div>`;

  if (!findings.length) {
    html += `<div class="sr-empty">No screens or chains fired on this data. That is <b>not</b> a clean bill of health —
      it means these particular rules found nothing in these rows. Add access events to enable fusion, or widen the export.</div>`;
    host.innerHTML = html;
    return;
  }

  for (const f of findings) {
    const m = SEV_META[f.severity] || SEV_META.info;
    const fusion = f.rule.startsWith("fusion-");
    html += `<div class="sr-find" style="border-left-color:${m.c}">
      <div class="ft">
        <span class="sr-chip" style="background:${m.c};padding:2px 9px;font-size:.68rem">${m.label}</span>
        <span class="tt">${esc(f.title)}</span>
        ${f.money > 0 ? `<span class="mm" style="color:${m.c}">${fmtMoney(f.money)}</span>` : ""}
      </div>
      <div class="fmeta">
        <span>${fusion ? "FUSION chain" : "rule"}: <code>${esc(f.rule)}</code></span>
        <span title="${esc(SOUND_HELP[f.soundness] || "")}">soundness: <b>${esc(f.soundness)}</b></span>
        ${f.vendor ? `<span>vendor: ${esc(f.vendor)}</span>` : ""}
        ${f.rows.length ? `<span>rows: ${f.rows.slice(0, 12).join(", ")}${f.rows.length > 12 ? "…" : ""}</span>` : ""}
      </div>
      <p class="fwhy">${esc(f.why)}</p>
      ${f.evidence && f.evidence.length ? `<details><summary>Evidence (${f.evidence.length})</summary><div class="fev">${f.evidence.map(esc).join("\n")}</div></details>` : ""}
    </div>`;
  }
  host.innerHTML = html;
  const sinkRow = host.querySelector("#srSink");
  if (sinkRow) attachSinkButton(sinkRow, () => ({ findings: fusionFindings(res), sample }), "strongroom", { dataset: "payments + access events" });
}
