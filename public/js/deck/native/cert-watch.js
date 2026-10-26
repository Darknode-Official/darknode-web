// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Native Certificate Watch: the newest publicly logged certificate for each domain
// (certificate transparency via ct-fetch), banded by days to expiry with tls-engine.

import { fetchCertRows } from "/js/dataprotect/ct-fetch.js?v=20261025g";
import { buildEntry, summarizeFleet, parseDomains, BANDS } from "/js/dataprotect/tls-engine.js";
import { tlsFleetFindings } from "/js/dataprotect/dp-sink.js";
import { attachSinkButton } from "/js/core/sink.js";
import { esc, toast, recordRun, readList, writeList, pool, download } from "./ui.js";

export function mount(el, { space, mode }) {
  const fleet = mode === "fleet";
  el.innerHTML = `
    <div class="ns-card"><h2>${fleet ? "Certificate fleet" : "Certificate watch"}<span class="r" id="nsCwCount"></span></h2>
      <p class="ns-sub">${fleet
        ? "Track expiry across every public hostname. Reads the newest certificate each host has in the public certificate-transparency logs, so it also catches hosts nobody remembers."
        : "Know before your site's certificate expires and visitors see a security warning. Add the domains you run; the list is saved in this browser."}</p>
      <textarea class="ns-ta" id="nsCwIn" aria-label="Domains to watch" style="min-height:${fleet ? 110 : 70}px" placeholder="One domain per line" spellcheck="false"></textarea>
      <div class="ns-row"><button class="ns-btn" id="nsCwGo">Check certificates</button><button class="ns-btn ghost" id="nsCwCsv" disabled>Export CSV</button>${fleet ? `<button class="ns-btn ghost" id="nsCwPf" hidden>Add portfolio domains</button>` : ""}<span class="ns-help" id="nsCwSt" style="margin:0"></span></div>
      <p class="ns-help">Certificate-transparency lookups are public. Up to ${fleet ? 200 : 20} domains.</p></div>
    <div id="nsCwOut"></div>`;
  const ta = el.querySelector("#nsCwIn"), go = el.querySelector("#nsCwGo"), csv = el.querySelector("#nsCwCsv"), st = el.querySelector("#nsCwSt"), out = el.querySelector("#nsCwOut");
  ta.value = readList(space, "certs").join("\n");
  const cnt = () => { const n = parseDomains(ta.value).length; el.querySelector("#nsCwCount").textContent = n ? n + " domain" + (n === 1 ? "" : "s") : ""; };
  ta.oninput = cnt; cnt();
  // the fleet usually is the domain portfolio: pull its domains in on request (never automatically)
  const pf = el.querySelector("#nsCwPf");
  const missing = () => { const have = new Set(parseDomains(ta.value)); return readList(space, "domains").filter((d) => !have.has(d)); };
  const pfPaint = () => { if (!pf) return; const n = missing().length; pf.hidden = !n; pf.textContent = "Add " + n + " portfolio domain" + (n === 1 ? "" : "s"); };
  if (pf) {
    pf.onclick = () => { const add = missing(); if (!add.length) return pfPaint(); ta.value = (ta.value.trim() ? ta.value.trim() + "\n" : "") + add.join("\n"); cnt(); pfPaint(); toast("Added " + add.length + " domain" + (add.length === 1 ? "" : "s") + " from the portfolio"); };
    ta.addEventListener("input", pfPaint); pfPaint();
    // the portfolio tab may change while this one stays mounted
    new IntersectionObserver((e) => { if (e[0].isIntersecting) pfPaint(); }).observe(ta);
  }
  let entries = [];

  const render = (pending) => {
    const s = summarizeFleet(entries.filter(Boolean));
    const kpi = (v, l, c) => `<div class="ns-kpi" style="--c:${c}"><div class="v">${v}</div><div class="l">${l}</div></div>`;
    out.innerHTML = `
      <div class="ns-kpis">${kpi(s.counts.expired, "Expired", BANDS.expired.c)}${kpi(s.counts.urgent + s.counts.soon, "Expire within 30 days", BANDS.urgent.c)}${kpi(s.counts.watch, "Within 60 days", BANDS.watch.c)}${kpi(s.counts.ok, "Healthy", BANDS.ok.c)}</div>
      <div class="ns-card"><h2>Expiry, soonest first<span class="r" data-act></span></h2><div class="ns-scroll"><table class="ns-tbl">
        <thead><tr><th>Status</th><th>Domain</th><th>Days left</th><th>Expires</th><th>Issuer</th></tr></thead><tbody>
        ${s.list.map((e) => `<tr><td><span class="ns-pill" style="background:${e.band.c}">${esc(e.band.label)}</span></td><td><b>${esc(e.domain)}</b></td><td style="font-weight:800;color:${e.band.c}">${e.daysLeft == null ? "-" : e.daysLeft}</td><td>${esc(e.notAfter ? String(e.notAfter).slice(0, 10) : "-")}</td><td>${esc(e.issuer || (e.ok ? "" : e.unreachable ? "Lookup failed: the certificate logs did not answer. Check again in a minute." : "No certificate found in CT logs"))}</td></tr>`).join("")}
        ${pending ? `<tr><td colspan="5" style="color:var(--ns-mut)"><span class="ns-spin"></span>${pending} still checking...</td></tr>` : ""}
        </tbody></table></div></div>`;
    if (!pending && s.total) attachSinkButton(out.querySelector("[data-act]"), () => ({ findings: tlsFleetFindings(s.list) }), "tlsfleet", { dataset: fleet ? "certificate fleet" : "certificate watch" });
    return s;
  };

  go.onclick = async () => {
    const list = parseDomains(ta.value).slice(0, fleet ? 200 : 20);
    if (!list.length) { toast("Add at least one domain"); return; }
    // say which lines were not domain names instead of dropping them silently
    const bad = [...new Set(ta.value.split(/[\n,;]+/).map((t) => t.trim()).filter((t) => t && !parseDomains(t).length))];
    const skipped = bad.length ? "Skipped " + bad.length + " that " + (bad.length === 1 ? "is" : "are") + " not a domain name: " + bad.slice(0, 5).join(", ") + (bad.length > 5 ? ", ..." : "") + ". " : "";
    writeList(space, "certs", list);
    go.disabled = true; csv.disabled = true; entries = new Array(list.length);
    let done = 0; render(list.length);
    await pool(list, 4, async (d) => { const rows = await fetchCertRows(d); return Object.assign(buildEntry(d, rows), { unreachable: !!rows.unreachable }); }, (e, i) => {
      entries[i] = e && e.domain ? e : Object.assign(buildEntry(list[i], []), { unreachable: true }); done++; st.textContent = skipped + done + " / " + list.length + " checked"; render(list.length - done);
    });
    const s = render(0);
    go.disabled = false; csv.disabled = false;
    recordRun(space, { tool: "certs", target: list.length + " domain" + (list.length === 1 ? "" : "s"),
      summary: s.alerting ? s.alerting + " expiring within 30 days or expired" : s.counts.unknown ? s.counts.unknown + " could not be checked" : "All certificates healthy" + (s.soonest != null ? ", soonest in " + s.soonest + " days" : ""),
      level: s.counts.expired || s.counts.urgent ? "bad" : s.alerting || s.counts.unknown ? "warn" : "good", counts: s.counts });
  };
  csv.onclick = () => {
    const q = (v) => '"' + String(v == null ? "" : v).replace(/"/g, '""') + '"';
    const s = summarizeFleet(entries.filter(Boolean));
    download("certificates.csv", [["domain", "status", "days_left", "not_after", "issuer"].join(",")].concat(s.list.map((e) => [e.domain, e.band.label, e.daysLeft, e.notAfter, e.issuer].map(q).join(","))).join("\n"), "text/csv");
  };
}
