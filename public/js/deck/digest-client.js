// Weekly email digest, browser side. The server (worker/digest.js) holds the opt-in and sends
// the mail; this file reads and saves the setting and keeps the server's copy of the user's
// watched certificates current, so the Monday email reflects their latest check.
import { api } from "/js/core/api.js";
import { readList } from "/js/deck/native/ui.js";

const SPACES = ["personal", "enterprise"];
const flagKey = () => "dn_digest_on_" + ((typeof window !== "undefined" && window.__dnUid) || "");
const syncKey = () => "dn_digest_sync_" + ((typeof window !== "undefined" && window.__dnUid) || "");

export const getDigest = () => api("/api/digest/prefs", { failed: "Could not load the digest setting" });
export const sendDigestTest = () => api("/api/digest/test", { method: "POST", body: {}, failed: "Could not send the test email" });

// What this browser knows: saved domain lists and the last certificate check's results.
export function localWatch() {
  const domains = new Set(), certs = new Map();
  let certsAt = 0;
  for (const sp of SPACES) {
    for (const d of readList(sp, "domains").concat(readList(sp, "certs"))) if (typeof d === "string" && d) domains.add(d.toLowerCase());
    const at = Number(readList(sp, "certresAt")[0]) || 0;
    for (const c of readList(sp, "certres")) if (c && c.domain && !certs.has(c.domain)) certs.set(c.domain, c);
    if (at > certsAt) certsAt = at;
  }
  const out = { domains: [...domains].slice(0, 50) };
  if (certs.size) { out.certs = [...certs.values()].slice(0, 200); out.certsAt = certsAt || Date.now(); }
  return out;
}

export async function saveDigest(on) {
  const r = await api("/api/digest/prefs", { method: "POST", body: { on, ...localWatch() }, failed: "Could not save the digest setting" });
  try { localStorage.setItem(flagKey(), r && r.on ? "1" : "0"); localStorage.setItem(syncKey(), JSON.stringify(localWatch())); } catch (_) {}
  return r;
}
export function rememberDigest(on) { try { localStorage.setItem(flagKey(), on ? "1" : "0"); } catch (_) {} }

// Called when the Deck opens: if this account has the digest on and its watched lists changed
// since the last upload, send the new lists. Silent; a failure just tries again next time.
export async function syncDigestIfOn() {
  try {
    if (localStorage.getItem(flagKey()) !== "1") return;
    const now = JSON.stringify(localWatch());
    if (localStorage.getItem(syncKey()) === now) return;
    await api("/api/digest/prefs", { method: "POST", body: JSON.parse(now) });
    localStorage.setItem(syncKey(), now);
  } catch (_) {}
}
