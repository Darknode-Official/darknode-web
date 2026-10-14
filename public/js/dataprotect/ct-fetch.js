// ct-fetch.js — fetch certificate-transparency rows for a domain, resilient to
// crt.sh outages (it is frequently 502/down). Tries crt.sh first, then falls
// back to SSLMate's certspotter API, normalising both into crt.sh-shaped rows
// ({ issuer_name, not_after, not_before, name_value }) so the pure engine
// (newestCert in posture-engine.js) consumes either source unchanged.
// All fetches go through the Darknode proxy.

import { dnFetch } from "/js/net.js";

function fromCertspotter(arr) {
  if (!Array.isArray(arr)) return [];
  return arr.map((x) => ({
    issuer_name: (x.issuer && (x.issuer.name || x.issuer.friendly_name)) || "",
    not_after: x.not_after || "",
    not_before: x.not_before || "",
    name_value: (x.dns_names || []).join("\n"),
  }));
}

// Returns an array of CT rows (possibly empty). Never throws.
export async function fetchCertRows(domain) {
  const d = encodeURIComponent(domain);
  // 1) crt.sh (richest, but flaky)
  try {
    const r = await dnFetch("https://crt.sh/?output=json&exclude=expired&q=" + d, { raw: true, timeout: 15000 });
    if (r.status && r.status < 500 && r.body && r.body.trim().startsWith("[")) {
      const a = JSON.parse(r.body);
      if (Array.isArray(a) && a.length) return a;
    }
  } catch (_) {}
  // 2) certspotter fallback
  try {
    const url = "https://api.certspotter.com/v1/issuances?include_subdomains=false" +
      "&expand=issuer&expand=not_before&expand=not_after&expand=dns_names&domain=" + d;
    const r = await dnFetch(url, { raw: true, timeout: 15000 });
    if (r.body && r.body.trim().startsWith("[")) {
      const rows = fromCertspotter(JSON.parse(r.body));
      if (rows.length) return rows;
    }
  } catch (_) {}
  return [];
}

export default { fetchCertRows };
