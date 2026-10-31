// Email notifications for Darknode — sent client-side via EmailJS (emailjs.com),
// the only way a static site can send email with no backend.
//
// SETUP (≈5 min, free tier):
//   1. Create an account at https://www.emailjs.com and add an Email Service
//      (connect your Gmail). Copy the Service ID.
//   2. Create TWO email templates and copy each Template ID:
//        • Code template   — set the template's "To email" to {{to_email}}.
//          Use variables: {{name}}, {{code}}.  e.g. body: "Your Darknode code is {{code}}".
//        • Alert template  — "To email" = {{to_email}}.
//          Variables: {{name}}, {{time}}, {{device}}.
//   3. Account → General → copy your Public Key.
//   4. Paste all four values below, add https://api.emailjs.com to the CSP
//      connect-src in firebase.json, and set EMAILJS_CSP_ALLOWED. Until then, the
//      site falls back to Firebase's built-in email-verification link and skips
//      login alerts.
const EMAILJS = {
  publicKey: "wydk8Uuzp3W0WhbZj",
  serviceId: "service_ghf1upo",
  codeTemplate: "YOUR_CODE_TEMPLATE_ID",
  alertTemplate: "YOUR_ALERT_TEMPLATE_ID",
  // Free-form announcement/outage notice. Template "To email" = {{to_email}};
  // variables: {{name}}, {{subject}}, {{message}}. Used by sendAnnouncement().
  announceTemplate: "template_u8nmqoe",
};

// EmailJS posts to https://api.emailjs.com, which is NOT in the CSP connect-src in
// firebase.json, so every send is blocked in the browser today. Flip this to true only
// after adding that origin to connect-src (both hosting sites) and deploying the headers.
// Before enabling: the code is checked in the browser and Firestore rules forbid a client
// setting codeVerified, so verification must move server-side (Worker + Admin SDK) first.
const EMAILJS_CSP_ALLOWED = false;
const _set = (v) => !!v && !v.startsWith("YOUR_");

// True only when a send can actually succeed: CSP allows EmailJS and the service plus the
// code template are set. While false, sign-up uses Firebase's own verification link (which
// works) instead of a 6-digit code that could never arrive, and login alerts are skipped.
export const emailConfigured = () =>
  EMAILJS_CSP_ALLOWED && _set(EMAILJS.publicKey) && _set(EMAILJS.serviceId) && _set(EMAILJS.codeTemplate);

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

// Free-form announcement / outage notice (e.g. explaining an incident to a user).
// Returns {ok,error}. Admin-only in practice; also exposed as window.dnSendEmail so
// the owner can send a one-off from the console on the live site once configured.
export async function sendAnnouncement(toEmail, subject, message, name) {
  if (!EMAILJS_CSP_ALLOWED || !_set(EMAILJS.publicKey) || !_set(EMAILJS.serviceId) || !_set(EMAILJS.announceTemplate))
    return { ok: false, error: "Email alerts not configured (EmailJS is blocked by the CSP connect-src)" };
  try {
    const e = await lib();
    await e.send(EMAILJS.serviceId, EMAILJS.announceTemplate, {
      to_email: toEmail, email: toEmail, name: name || toEmail, subject: subject || "", message: message || "",
    });
    return { ok: true };
  } catch (err) { return { ok: false, error: (err && err.text) || String(err) }; }
}
try { window.dnSendEmail = sendAnnouncement; } catch (_) {}

// Crypto-secure 6-digit code. Rejection-samples a 32-bit value to avoid modulo
// bias across the 900000-wide range, falling back to Math.random only if the
// Web Crypto API is somehow unavailable. (This path is dormant unless EmailJS is
// configured — see emailConfigured() — but must not ship a predictable code.)
export function genCode() {
  try {
    const span = 900000, max = Math.floor(0xffffffff / span) * span, u = new Uint32Array(1);
    let r; do { crypto.getRandomValues(u); r = u[0]; } while (r >= max);
    return String(100000 + (r % span));
  } catch (_) {
    return String(Math.floor(100000 + Math.random() * 900000));
  }
}

export async function hashCode(code) {
  const b = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("darknode:" + code));
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
