// Email notifications for Sentinel — sent client-side via EmailJS (emailjs.com),
// the only way a static site can send email with no backend.
//
// SETUP (≈5 min, free tier):
//   1. Create an account at https://www.emailjs.com and add an Email Service
//      (connect your Gmail). Copy the Service ID.
//   2. Create TWO email templates and copy each Template ID:
//        • Code template   — set the template's "To email" to {{to_email}}.
//          Use variables: {{name}}, {{code}}.  e.g. body: "Your Sentinel code is {{code}}".
//        • Alert template  — "To email" = {{to_email}}.
//          Variables: {{name}}, {{time}}, {{device}}.
//   3. Account → General → copy your Public Key.
//   4. Paste all four values below. Until then, the site falls back to Firebase's
//      built-in email-verification link and skips login alerts.
const EMAILJS = {
  publicKey: "YOUR_PUBLIC_KEY",
  serviceId: "YOUR_SERVICE_ID",
  codeTemplate: "YOUR_CODE_TEMPLATE_ID",
  alertTemplate: "YOUR_ALERT_TEMPLATE_ID",
};

export const emailConfigured = () =>
  EMAILJS.publicKey && !EMAILJS.publicKey.startsWith("YOUR_") &&
  EMAILJS.serviceId && !EMAILJS.serviceId.startsWith("YOUR_");

let _lib = null;
async function lib() {
  if (_lib) return _lib;
  _lib = (await import("https://cdn.jsdelivr.net/npm/@emailjs/browser@4/+esm")).default;
  _lib.init({ publicKey: EMAILJS.publicKey });
  return _lib;
}

export async function sendCode(toEmail, code, name) {
  if (!emailConfigured()) return { ok: false, error: "email not configured" };
  try {
    const e = await lib();
    await e.send(EMAILJS.serviceId, EMAILJS.codeTemplate, { to_email: toEmail, email: toEmail, name: name || toEmail, code });
    return { ok: true };
  } catch (err) { return { ok: false, error: (err && err.text) || String(err) }; }
}

export async function sendLoginAlert(toEmail, info) {
  if (!emailConfigured() || !EMAILJS.alertTemplate || EMAILJS.alertTemplate.startsWith("YOUR_")) return { ok: false };
  try {
    const e = await lib();
    await e.send(EMAILJS.serviceId, EMAILJS.alertTemplate, { to_email: toEmail, email: toEmail, ...info });
    return { ok: true };
  } catch (err) { return { ok: false }; }
}

export function genCode() { return String(Math.floor(100000 + Math.random() * 900000)); }

export async function hashCode(code) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("sentinel:" + code));
  return [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export function deviceInfo() {
  let id;
  try { id = localStorage.getItem("sw_device"); if (!id) { id = (crypto.randomUUID ? crypto.randomUUID() : String(Math.random()).slice(2)); localStorage.setItem("sw_device", id); } } catch (_) { id = "unknown"; }
  const ua = navigator.userAgent;
  const browser = /Edg/.test(ua) ? "Edge" : /OPR/.test(ua) ? "Opera" : /Chrome/.test(ua) ? "Chrome" : /Firefox/.test(ua) ? "Firefox" : /Safari/.test(ua) ? "Safari" : "Browser";
  const osn = /Windows/.test(ua) ? "Windows" : /Android/.test(ua) ? "Android" : /iPhone|iPad/.test(ua) ? "iOS" : /Mac/.test(ua) ? "macOS" : /Linux/.test(ua) ? "Linux" : "device";
  return { id, label: browser + " on " + osn };
}
