// POST /api/v1/usage (signed-in): a product heartbeat, so the owner's admin panel can see
// who uses Nexus, the desktop app and the app's virtual machines. Only signed-in clients
// send it (Nexus once a sign-in exists, the app's Deck when the desktop bridge is present),
// at most every few hours, and they can turn it off. Stored with the service account in
// usage/{uid}; the rules let only the owner read it and nobody write it directly.
//
// usage/{uid} = { email, nexus: { first, last, version, os, pings }, app: {...},
//                 vm: { first, last, count, running, lastStart } }
import { googleToken } from "./digest.js";

export const PRODUCTS = new Set(["nexus", "app"]);
const OSES = new Set(["linux", "darwin", "win32"]);
const MIN_GAP_MS = 10 * 60 * 1000; // a burst of pings writes once

const str = (v) => ({ stringValue: String(v) });
const int = (v) => ({ integerValue: String(Math.trunc(v)) });
const ts = (ms) => ({ timestampValue: new Date(ms).toISOString() });
const map = (o) => ({ mapValue: { fields: o } });
const msOf = (f) => (f && f.timestampValue ? Date.parse(f.timestampValue) : 0);
const numOf = (f) => (f && f.integerValue != null ? Number(f.integerValue) : 0);

// -> { product, version, os, vm } | { error }
export function validatePing(b) {
  if (!b || typeof b !== "object") return { error: "Invalid JSON body" };
  const product = String(b.product || "");
  if (!PRODUCTS.has(product)) return { error: "product must be nexus or app" };
  const version = typeof b.version === "string" && /^[\w.+-]{1,24}$/.test(b.version) ? b.version : "";
  const os = OSES.has(b.os) ? b.os : "";
  let vm = null;
  if (product === "app" && b.vm && typeof b.vm === "object") {
    const count = Math.max(0, Math.min(999, Math.trunc(Number(b.vm.count) || 0)));
    const running = Math.max(0, Math.min(count, Math.trunc(Number(b.vm.running) || 0)));
    const ls = Number(b.vm.lastStart) || 0;
    vm = { count, running, lastStart: ls > 1.5e12 && ls <= Date.now() + 60000 ? ls : 0 };
  }
  return { product, version, os, vm };
}

// The new document fields given the stored ones. Returns null when nothing should be written
// (the same product pinged moments ago and nothing about its VMs changed).
export function mergeUsage(prev, ping, email, now = Date.now()) {
  const p = (prev && prev.fields) || {};
  const cur = (p[ping.product] && p[ping.product].mapValue && p[ping.product].mapValue.fields) || {};
  const last = msOf(cur.last);
  const oldVm = (p.vm && p.vm.mapValue && p.vm.mapValue.fields) || null;
  const vmChanged = !!ping.vm && (!oldVm || numOf(oldVm.count) !== ping.vm.count || numOf(oldVm.running) !== ping.vm.running || msOf(oldVm.lastStart) !== ping.vm.lastStart);
  if (last && now - last < MIN_GAP_MS && !vmChanged && (cur.version && cur.version.stringValue) === ping.version) return null;
  const fields = {
    email: str(email || (p.email && p.email.stringValue) || ""),
    [ping.product]: map({
      first: cur.first || ts(now), last: ts(now),
      version: str(ping.version), os: str(ping.os),
      pings: int(numOf(cur.pings) + 1),
    }),
  };
  // A VM counts as "used" once the app reports at least one; last = the latest start seen.
  if (ping.vm && (ping.vm.count > 0 || oldVm)) {
    const started = Math.max(ping.vm.lastStart, msOf(oldVm && oldVm.lastStart));
    fields.vm = map({
      first: (oldVm && oldVm.first) || ts(now),
      last: ts(ping.vm.running > 0 ? now : (started || now)),
      count: int(ping.vm.count), running: int(ping.vm.running),
      ...(started ? { lastStart: ts(started) } : {}),
    });
  }
  return fields;
}

export async function handleUsage(request, env, json, principal, opts = {}) {
  if (!principal || !principal.uid) return json({ error: "Sign in first." }, 401);
  if (!env.FIREBASE_PROJECT_ID) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const raw = await request.text();
  if (raw.length > 2048) return json({ error: "Request too large." }, 413);
  let b; try { b = JSON.parse(raw); } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
  const ping = validatePing(b);
  if (ping.error) return json({ error: ping.error }, 400);
  const doFetch = opts.fetch || fetch;
  let token;
  try { token = await (opts.token || googleToken)(env); }
  catch (e) { return json({ error: "Server credentials unavailable: " + e.message }, 503); }
  const url = "https://firestore.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/databases/(default)/documents/usage/" + encodeURIComponent(principal.uid);
  const auth = { Authorization: "Bearer " + token };
  const g = await doFetch(url, { headers: auth });
  if (!g.ok && g.status !== 404) return json({ error: "Could not read usage (" + g.status + ")" }, 502);
  const prev = g.ok ? await g.json().catch(() => null) : null;
  const fields = mergeUsage(prev, ping, principal.email, opts.now || Date.now());
  if (!fields) return json({ ok: true, skipped: true });
  const mask = Object.keys(fields).map((k) => "updateMask.fieldPaths=" + k).join("&");
  const w = await doFetch(url + "?" + mask, { method: "PATCH", headers: { ...auth, "Content-Type": "application/json" }, body: JSON.stringify({ fields }) });
  if (!w.ok) return json({ error: "Could not save usage (" + w.status + ")" }, 502);
  return json({ ok: true });
}
