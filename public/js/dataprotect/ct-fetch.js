// ct-fetch.js — fetch certificate-transparency rows for a domain, resilient to
// crt.sh outages (it is frequently 502/down). Tries crt.sh first, then falls
// back to SSLMate's certspotter API, normalising both into crt.sh-shaped rows
// ({ issuer_name, not_after, not_before, name_value }) so the pure engine
// (newestCert in posture-engine.js) consumes either source unchanged.
// All fetches go through the Darknode proxy.

import { dnFetch, dnFetchJSON } from "/js/net.js";

function fromCertspotter(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map((x) => ({
    issuer_name: (x.issuer && (x.issuer.name || x.issuer.friendly_name)) || "",
    not_after: x.not_after || "",
    not_before: x.not_before || "",
    name_value: (x.dns_names || []).join("\n"),
  }));
}

// A certificate covers a host when it names it exactly or through a one-label wildcard
// (*.example.com covers www.example.com, not example.com or a.b.example.com).
export function certCovers(names, host) {
  host = String(host || "").toLowerCase().replace(/\.$/, "");
  const dot = host.indexOf("."), wild = dot > 0 && host.indexOf(".", dot + 1) > 0 ? "*" + host.slice(dot) : null;
  return String(names || "").toLowerCase().split(/[\n,\s]+/).some((n) => n === host || (wild && n === wild));
}

// Returns an array of CT rows (possibly empty). Never throws.
// Only certificates that cover the host are returned: a log search for example.com also
// lists registry.example.com-only certificates, and a host served by a wildcard is only
// found by asking for *.parent. An empty result carries .unreachable when neither log
// answered, so a caller can tell "nothing logged" from "could not ask".
export async function fetchCertRows(domain) {
  const host = String(domain || "").toLowerCase().replace(/\.$/, "");
  const dot = host.indexOf("."), wild = dot > 0 && host.indexOf(".", dot + 1) > 0 ? "*" + host.slice(dot) : null;
  const cover = (rows) => rows.filter((r) => certCovers(r.name_value || r.common_name, host));
  let answered = false;
  // 1) crt.sh (richest, but flaky and often slower than 10 s: past 15 s the proxy waits upstream longer)
  for (const q of wild ? [host, wild] : [host]) {
    try {
      const r = await dnFetch("https://crt.sh/?output=json&exclude=expired&q=" + encodeURIComponent(q), { raw: true, timeout: 30000 });
      if (r.status && r.status < 500 && r.body && r.body.trim().startsWith("[")) {
        const a = JSON.parse(r.body);
        answered = true;
        const rows = Array.isArray(a) ? cover(a) : [];
        if (rows.length) return rows;
      } else if (!answered) break;
    } catch (_) { if (!answered) break; }
  }
  // 2) certspotter fallback (the parent domain's issuances carry its wildcard certificates)
  for (const q of wild ? [host, wild.slice(2)] : [host]) {
    try {
      const url = "https://api.certspotter.com/v1/issuances?include_subdomains=false" +
        "&expand=issuer&expand=not_before&expand=not_after&expand=dns_names&domain=" + encodeURIComponent(q);
      const r = await dnFetch(url, { raw: true, timeout: 15000 });
      if (r.body && r.body.trim().startsWith("[")) {
        const rows = cover(fromCertspotter(JSON.parse(r.body)));
        answered = true;
        if (rows.length) return rows;
      }
    } catch (_) {}
  }
  return answered ? [] : Object.assign([], { unreachable: true });
}

// Subdomain discovery: every name under `domain` in CT. crt.sh (%.domain, full
// history) first; Cert Spotter when crt.sh doesn't answer (unexpired certificates,
// first page only). Unlike fetchCertRows this THROWS when both fail, so a caller can
// tell "unreachable" from "no subdomains"; the array carries .source.
const ctName = (n, d, set) => {
  n = String(n || "").trim().toLowerCase().replace(/^\*\./, "");
  if ((n === d || n.endsWith("." + d)) && /^[a-z0-9.\-_]+$/.test(n)) set.add(n); // "." + d: notexample.com is not under example.com
};
const errMsg = (e) => String((e && e.message) || e || "error").replace(/\.$/, "");
export async function fetchSubdomainNames(domain) {
  const d = String(domain || "").trim().toLowerCase(), set = new Set();
  try {
    // crt.sh can return a multi-megabyte JSON for popular domains; ask for the proxy's large-body cap
    const rows = await dnFetchJSON("https://crt.sh/?q=%25." + encodeURIComponent(d) + "&output=json", { timeout: 30000, max: 4000000 });
    (Array.isArray(rows) ? rows : []).forEach((r) => String(r.name_value || "").split(/\n/).forEach((n) => ctName(n, d, set)));
    return Object.assign([...set].sort(), { source: "crt.sh" });
  } catch (e1) {
    let rows;
    try { rows = await dnFetchJSON("https://api.certspotter.com/v1/issuances?domain=" + encodeURIComponent(d) + "&include_subdomains=true&expand=dns_names", { timeout: 20000 }); }
    catch (e2) { throw new Error("Certificate transparency is unreachable right now (crt.sh: " + errMsg(e1) + "; Cert Spotter: " + errMsg(e2) + "). Try again in a minute."); }
    (Array.isArray(rows) ? rows : []).forEach((r) => (r.dns_names || []).forEach((n) => ctName(n, d, set)));
    return Object.assign([...set].sort(), { source: "certspotter" });
  }
}

export default { fetchCertRows, fetchSubdomainNames };
