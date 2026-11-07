// Desktop app usage heartbeat. Inside the Darknode desktop app (window.darknode.desktop),
// a signed-in Deck tells the Worker which app version and OS it runs on, plus how many
// virtual machines the app's VM manager holds, at most every 6 hours. The owner's admin
// panel lists it. Settings > "Share app usage" turns it off. Nothing is sent from a browser.

export const OFF_KEY = "dn_usage_off";
const LAST_KEY = "dn_usage_app_at";
const EVERY_MS = 6 * 3600e3;

const ls = () => { try { return window.localStorage; } catch (_) { return null; } };
export const usageOff = (store = ls()) => !!store && store.getItem(OFF_KEY) === "1";
export function setUsageOff(off, store = ls()) { if (!store) return; off ? store.setItem(OFF_KEY, "1") : store.removeItem(OFF_KEY); }
export const inDesktopApp = (w = globalThis) => !!(w.darknode && w.darknode.desktop && w.darknode.desktop.shell === "web");

// deps: { win, store, api, now } (tests pass fakes). -> "sent" | "skipped" | "off" | "not-app" | "failed"
export async function pingAppUsage(deps = {}) {
  const w = deps.win || globalThis, store = deps.store || ls(), now = deps.now || Date.now();
  if (!inDesktopApp(w)) return "not-app";
  if (usageOff(store)) return "off";
  const last = Number((store && store.getItem(LAST_KEY)) || 0);
  if (last && now - last < EVERY_MS) return "skipped";
  const d = w.darknode.desktop, native = w.darknode.native || {};
  const body = { product: "app", version: String(d.version || ""), os: String(d.platform || "") };
  if (typeof native.vmUsage === "function") {
    try { const v = await native.vmUsage(); if (v && typeof v === "object") body.vm = { count: v.count, running: v.running, lastStart: v.lastStart }; } catch (_) {}
  }
  try {
    const api = deps.api || (await import("/js/core/api.js")).api;
    await api("/api/v1/usage", { method: "POST", body });
    if (store) store.setItem(LAST_KEY, String(now));
    return "sent";
  } catch (_) { return "failed"; }
}
