// Weekly email digest. Opt-in only.
//
// What a subscriber gets each week, all from real data:
//   - CISA KEV entries added in the last 7 days (public/data/feeds/kev-recent.json, written
//     daily by the refresh-feeds workflow; kept tiny so this stays inside the free plan's CPU)
//   - their watched certificates that are expired or expire within 30 days, as of the last
//     check they ran in the Deck (the date is stated), and a nudge when that check is old
//
// Storage: Firestore digest/{uid} = { on: bool, json: string }. Clients have no rules access to
// this collection (default deny); only this Worker reads and writes it, with the service
// account in the FIREBASE_SA secret. Mail goes through Resend (RESEND_KEY).
//
// Pure builders (buildDigest, certRows, validatePrefs, unsubToken) are unit-tested; the rest is
// thin REST plumbing.

const SITE = "https://darknode.ai";
const FROM = "Darknode <digest@darknode.ai>";
const DAY = 86400000;
const MAX_DOMAINS = 50, MAX_CERTS = 200;
const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?:\.[a-z0-9-]{1,63})+$/;

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

// ---- pure ------------------------------------------------------------------------------

// Clean what a client sends. -> { ok, prefs } | { ok:false, error }
export function validatePrefs(body, prev = {}) {
  if (!body || typeof body !== "object") return { ok: false, error: "Invalid body" };
  const out = { ...prev };
  if (body.on !== undefined) {
    if (typeof body.on !== "boolean") return { ok: false, error: "on must be true or false" };
    out.on = body.on;
  }
  if (body.domains !== undefined) {
    if (!Array.isArray(body.domains)) return { ok: false, error: "domains must be a list" };
    const d = [...new Set(body.domains.map((x) => String(x || "").trim().toLowerCase().replace(/\.$/, "")).filter((x) => DOMAIN_RE.test(x)))];
    out.domains = d.slice(0, MAX_DOMAINS);
  }
  if (body.certs !== undefined) {
    if (!Array.isArray(body.certs)) return { ok: false, error: "certs must be a list" };
    out.certs = body.certs.slice(0, MAX_CERTS).map((c) => {
      const domain = String((c && c.domain) || "").trim().toLowerCase();
      const t = Date.parse((c && c.notAfter) || "");
      if (!DOMAIN_RE.test(domain)) return null;
      return { domain, notAfter: isNaN(t) ? "" : new Date(t).toISOString(), issuer: String((c && c.issuer) || "").slice(0, 80) };
    }).filter(Boolean);
    const at = Number(body.certsAt);
    out.certsAt = Number.isFinite(at) && at > 0 && at <= Date.now() + DAY ? Math.floor(at) : Date.now();
  }
  return { ok: true, prefs: out };
}

// Certificates worth mentioning: expired or within 30 days (unknown expiry is listed too, as
// "could not be read"). Soonest first.
export function certRows(certs, now = Date.now()) {
  return (certs || []).map((c) => {
    const t = Date.parse(c.notAfter || "");
    return { ...c, daysLeft: isNaN(t) ? null : Math.floor((t - now) / DAY) };
  }).filter((c) => c.daysLeft === null || c.daysLeft <= 30)
    .sort((a, b) => (a.daysLeft ?? 1e9) - (b.daysLeft ?? 1e9));
}

// -> { subject, html, text, empty }  (empty = nothing worth sending)
export function buildDigest({ kev = [], prefs = {}, now = Date.now(), unsubUrl = "", test = false }) {
  const since = new Date(now - 7 * DAY).toISOString().slice(0, 10);
  const week = kev.filter((v) => v && v.cve && String(v.dateAdded || "") >= since)
    .sort((a, b) => String(b.dateAdded).localeCompare(String(a.dateAdded)));
  const certs = certRows(prefs.certs, now);
  const hasCerts = (prefs.certs || []).length > 0;
  const checkAge = prefs.certsAt ? Math.floor((now - prefs.certsAt) / DAY) : null;
  const stale = hasCerts && checkAge !== null && checkAge >= 7;
  const expiring = certs.filter((c) => c.daysLeft !== null);
  const empty = !week.length && !certs.length && !stale;

  const parts = [];
  if (expiring.length) parts.push(expiring.length + " certificate" + (expiring.length === 1 ? "" : "s") + " expiring");
  parts.push(week.length + " new exploited vulnerabilit" + (week.length === 1 ? "y" : "ies"));
  const subject = (test ? "[Test] " : "") + "Darknode weekly: " + parts.join(", ");

  const checkDate = prefs.certsAt ? new Date(prefs.certsAt).toISOString().slice(0, 10) : "";
  const certLabel = (c) => c.daysLeft === null ? "expiry could not be read" : c.daysLeft < 0 ? "expired " + -c.daysLeft + " day" + (c.daysLeft === -1 ? "" : "s") + " ago" : c.daysLeft === 0 ? "expires today" : "expires in " + c.daysLeft + " day" + (c.daysLeft === 1 ? "" : "s");

  // ---- text ----
  const t = [];
  t.push("Your Darknode weekly digest", "");
  if (certs.length || stale) {
    t.push("CERTIFICATES" + (checkDate ? " (as of your check on " + checkDate + ")" : ""));
    for (const c of certs) t.push("- " + c.domain + ": " + certLabel(c));
    if (stale) t.push("Your last certificate check was " + checkAge + " days ago. Re-run it: " + SITE + "/personal/certs");
    t.push("");
  }
  t.push("ADDED TO CISA KNOWN EXPLOITED VULNERABILITIES THIS WEEK (" + week.length + ")");
  if (!week.length) t.push("None this week.");
  for (const v of week.slice(0, 15)) t.push("- " + v.cve + " " + [v.vendor, v.product].filter(Boolean).join(" ") + (v.ransomware ? " [used in ransomware]" : "") + " (added " + v.dateAdded + (v.dueDate ? ", federal patch deadline " + v.dueDate : "") + ")");
  if (week.length > 15) t.push("...and " + (week.length - 15) + " more: " + SITE + "/threat");
  t.push("", "Open the Deck: " + SITE + "/overview", "", "You get this because you turned on the weekly digest in Darknode settings.", "Unsubscribe: " + unsubUrl);

  // ---- html ----
  const row = (l, r, warn) => `<tr><td style="padding:8px 0;border-top:1px solid #eceae4;font:600 13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;color:${warn ? "#c62828" : "#1d1c1a"}">${l}</td><td style="padding:8px 0 8px 12px;border-top:1px solid #eceae4;font:13px/1.4 -apple-system,Segoe UI,Roboto,sans-serif;color:#56544f">${r}</td></tr>`;
  const h2 = (s) => `<h2 style="margin:24px 0 8px;font:700 12px/1.3 -apple-system,Segoe UI,Roboto,sans-serif;letter-spacing:.05em;text-transform:uppercase;color:#56544f">${s}</h2>`;
  let body = "";
  if (certs.length || stale) {
    body += h2("Certificates" + (checkDate ? ` <span style="font-weight:500;text-transform:none;letter-spacing:0">as of your check on ${esc(checkDate)}</span>` : ""));
    if (certs.length) body += `<table role="presentation" width="100%" cellspacing="0" cellpadding="0">${certs.map((c) => row(esc(c.domain), esc(certLabel(c)), c.daysLeft === null || c.daysLeft <= 7)).join("")}</table>`;
    if (stale) body += `<p style="margin:10px 0 0;font:13px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#56544f">Your last certificate check was ${checkAge} days ago. <a href="${SITE}/personal/certs" style="color:#2552c6">Re-run it</a>.</p>`;
  }
  body += h2(`Added to CISA Known Exploited Vulnerabilities this week (${week.length})`);
  body += week.length
    ? `<table role="presentation" width="100%" cellspacing="0" cellpadding="0">${week.slice(0, 15).map((v) => row(
        `<a href="https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.cve)}" style="color:#1d1c1a;text-decoration:none;font-family:Menlo,Consolas,monospace">${esc(v.cve)}</a>`,
        esc([v.vendor, v.product].filter(Boolean).join(" ")) + (v.ransomware ? ' <span style="color:#c62828;font-weight:600">used in ransomware</span>' : "") + `<br><span style="color:#86837c">added ${esc(v.dateAdded)}${v.dueDate ? ", federal patch deadline " + esc(v.dueDate) : ""}</span>`)).join("")}</table>` +
      (week.length > 15 ? `<p style="margin:10px 0 0;font:13px -apple-system,Segoe UI,Roboto,sans-serif"><a href="${SITE}/threat" style="color:#2552c6">${week.length - 15} more in the Deck</a></p>` : "")
    : `<p style="margin:0;font:13px -apple-system,Segoe UI,Roboto,sans-serif;color:#56544f">None this week.</p>`;
  const html = `<!doctype html><html><body style="margin:0;background:#f7f7f4"><table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f7f7f4"><tr><td align="center" style="padding:24px 12px">
<table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:600px;background:#ffffff;border:1px solid #e6e4de;border-radius:10px"><tr><td style="padding:24px 28px">
<div style="font:700 18px/1.3 -apple-system,Segoe UI,Roboto,sans-serif;color:#1d1c1a">Your weekly digest</div>
<div style="margin-top:4px;font:13px -apple-system,Segoe UI,Roboto,sans-serif;color:#86837c">${esc(new Date(now).toISOString().slice(0, 10))}${test ? " · test send" : ""}</div>
${body}
<p style="margin:28px 0 0"><a href="${SITE}/overview" style="display:inline-block;background:#2552c6;color:#fff;text-decoration:none;font:600 14px -apple-system,Segoe UI,Roboto,sans-serif;padding:10px 18px;border-radius:7px">Open the Deck</a></p>
</td></tr></table>
<p style="max-width:600px;margin:14px auto 0;font:12px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;color:#86837c">You get this because you turned on the weekly digest in Darknode settings. <a href="${esc(unsubUrl)}" style="color:#86837c">Unsubscribe</a>.</p>
</td></tr></table></body></html>`;
  return { subject, html, text: t.join("\n"), empty };
}

// ---- crypto helpers ------------------------------------------------------------------------

const enc = new TextEncoder();
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uStr = (s) => b64u(enc.encode(s));

function readSA(env) {
  try { const sa = JSON.parse(env.FIREBASE_SA || ""); if (sa.client_email && sa.private_key) return sa; } catch (_) {}
  return null;
}

// HMAC of the uid, keyed from a server-only secret, for the unsubscribe link.
export async function unsubToken(uid, secret) {
  const k = await crypto.subtle.importKey("raw", await crypto.subtle.digest("SHA-256", enc.encode("digest-unsub:" + secret)), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(await crypto.subtle.sign("HMAC", k, enc.encode(uid))).slice(0, 32);
}
const unsubSecret = (env) => env.DIGEST_SECRET || (readSA(env) || {}).private_key || "";
async function unsubUrl(env, uid) {
  return (env.DIGEST_API_BASE || "https://darknode-proxy.darknode-ai.workers.dev") + "/api/digest/unsubscribe?u=" + encodeURIComponent(uid) + "&t=" + (await unsubToken(uid, unsubSecret(env)));
}

let _tok = null; // { token, exp }
async function googleToken(env) {
  if (_tok && _tok.exp > Date.now() + 60000) return _tok.token;
  const sa = readSA(env);
  if (!sa) throw new Error("FIREBASE_SA is not set");
  const now = Math.floor(Date.now() / 1000);
  const head = b64uStr(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claim = b64uStr(JSON.stringify({ iss: sa.client_email, scope: "https://www.googleapis.com/auth/cloud-platform", aud: "https://oauth2.googleapis.com/token", iat: now, exp: now + 3600 }));
  const pem = sa.private_key.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  const der = Uint8Array.from(atob(pem), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", der, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["sign"]);
  const sig = b64u(await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(head + "." + claim)));
  const r = await fetch("https://oauth2.googleapis.com/token", { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded" }, body: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion=" + head + "." + claim + "." + sig });
  const d = await r.json().catch(() => ({}));
  if (!r.ok || !d.access_token) throw new Error("Google token request failed (" + r.status + ")");
  _tok = { token: d.access_token, exp: Date.now() + (d.expires_in || 3600) * 1000 };
  return _tok.token;
}

// ---- Firestore (digest/{uid} = { on, json }) -------------------------------------------------

const fsBase = (env) => "https://firestore.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/databases/(default)/documents";
const fromDoc = (doc) => {
  const f = (doc && doc.fields) || {};
  let p = {}; try { p = JSON.parse((f.json && f.json.stringValue) || "{}") || {}; } catch (_) {}
  p.on = !!(f.on && f.on.booleanValue);
  return p;
};
const toFields = (p) => ({ on: { booleanValue: !!p.on }, json: { stringValue: JSON.stringify({ ...p, on: undefined }) } });

async function readPrefs(env, uid) {
  const r = await fetch(fsBase(env) + "/digest/" + encodeURIComponent(uid), { headers: { Authorization: "Bearer " + (await googleToken(env)) } });
  if (r.status === 404) return {};
  if (!r.ok) throw new Error("Could not read digest settings (" + r.status + ")");
  return fromDoc(await r.json());
}
async function writePrefs(env, uid, p) {
  const r = await fetch(fsBase(env) + "/digest/" + encodeURIComponent(uid), { method: "PATCH", headers: { Authorization: "Bearer " + (await googleToken(env)), "Content-Type": "application/json" }, body: JSON.stringify({ fields: toFields(p) }) });
  if (!r.ok) throw new Error("Could not save digest settings (" + r.status + ")");
}

async function loadKev() {
  const r = await fetch(SITE + "/data/feeds/kev-recent.json", { cf: { cacheTtl: 600 } });
  if (!r.ok) throw new Error("kev-recent.json " + r.status);
  const d = await r.json();
  return Array.isArray(d.data) ? d.data : [];
}

function mail(env, to, uid, d, url) {
  return {
    from: FROM, to: [to], subject: d.subject, html: d.html, text: d.text,
    headers: { "List-Unsubscribe": "<" + url + ">", "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" },
  };
}
async function resend(env, path, payload) {
  if (!env.RESEND_KEY) throw new Error("RESEND_KEY is not set");
  const r = await fetch("https://api.resend.com" + path, { method: "POST", headers: { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" }, body: JSON.stringify(payload) });
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error("Email provider error (" + r.status + "): " + String(d.message || d.error || "").slice(0, 160));
  return d;
}

// ---- HTTP: /api/digest/* (signed-in) and /api/digest/unsubscribe (link in the email) ---------

export async function handleDigest(request, env, rest, json, principal) {
  if (!readSA(env) || !env.RESEND_KEY) return json({ error: "The email digest is not configured on this server." }, 503);
  const uid = principal.uid, verified = !!(principal.claims && principal.claims.email_verified), email = principal.email || "";
  try {
    if (rest === "prefs" && request.method === "GET") {
      const p = await readPrefs(env, uid);
      return json({ on: !!p.on, email, verified, domains: p.domains || [], certs: (p.certs || []).length, certsAt: p.certsAt || null, lastSent: p.lastSent || null });
    }
    if (rest === "prefs" && request.method === "POST") {
      let body; try { body = JSON.parse(await request.text()); } catch (_) { return json({ error: "Invalid JSON body" }, 400); }
      const prev = await readPrefs(env, uid);
      const v = validatePrefs(body, prev);
      if (!v.ok) return json({ error: v.error }, 400);
      if (v.prefs.on && !(verified && email)) return json({ error: "Verify your email address first, then turn the digest on." }, 400);
      v.prefs.updated = Date.now();
      await writePrefs(env, uid, v.prefs);
      return json({ ok: true, on: !!v.prefs.on, domains: v.prefs.domains || [], certs: (v.prefs.certs || []).length });
    }
    if (rest === "test" && request.method === "POST") {
      if (!(verified && email)) return json({ error: "Verify your email address first." }, 400);
      const p = await readPrefs(env, uid);
      if (p.lastTest && Date.now() - p.lastTest < 10 * 60000) return json({ error: "A test was sent a few minutes ago. Try again in 10 minutes." }, 429);
      const url = await unsubUrl(env, uid);
      const d = buildDigest({ kev: await loadKev().catch(() => []), prefs: p, unsubUrl: url, test: true });
      await resend(env, "/emails", mail(env, email, uid, d, url));
      p.lastTest = Date.now();
      await writePrefs(env, uid, p);
      return json({ ok: true, to: email });
    }
    return json({ error: "Not found" }, 404);
  } catch (e) {
    return json({ error: String((e && e.message) || e).slice(0, 200) }, 502);
  }
}

const page = (title, msg) => new Response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title><body style="font:15px/1.5 -apple-system,Segoe UI,Roboto,sans-serif;background:#f7f7f4;color:#1d1c1a;display:grid;place-items:center;min-height:90vh;margin:0;padding:0 16px"><div style="max-width:440px;background:#fff;border:1px solid #e6e4de;border-radius:10px;padding:24px 28px"><h1 style="font-size:18px;margin:0 0 8px">${esc(title)}</h1><p style="margin:0;color:#56544f">${msg}</p></div>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store" } });

export async function handleUnsubscribe(request, env) {
  const u = new URL(request.url), uid = u.searchParams.get("u") || "", t = u.searchParams.get("t") || "";
  const ok = uid && uid.length <= 128 && t && t === (await unsubToken(uid, unsubSecret(env)));
  if (!ok) return page("Link not valid", "This unsubscribe link is incomplete or has expired. You can turn the digest off in Darknode settings.");
  try {
    const p = await readPrefs(env, uid);
    if (p.on) { p.on = false; p.updated = Date.now(); await writePrefs(env, uid, p); }
  } catch (_) { return page("Something went wrong", "We could not update your settings just now. Try the link again, or turn the digest off in Darknode settings."); }
  return page("Unsubscribed", `You will not get the weekly digest any more. You can turn it back on any time in <a href="${SITE}/settings" style="color:#2552c6">Darknode settings</a>.`);
}

// ---- cron: the weekly send ---------------------------------------------------------------------
// Subrequests per run stay small (free plan allows 50): token, query, account lookup, feed,
// one batch send per 100 subscribers, one commit.

export async function runDigest(env) {
  if (env.DIGEST_CRON !== "on") return { skipped: "DIGEST_CRON is not on" };
  if (!readSA(env) || !env.RESEND_KEY) return { skipped: "not configured" };
  const tok = await googleToken(env);
  const q = await fetch(fsBase(env) + ":runQuery", { method: "POST", headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" },
    body: JSON.stringify({ structuredQuery: { from: [{ collectionId: "digest" }], where: { fieldFilter: { field: { fieldPath: "on" }, op: "EQUAL", value: { booleanValue: true } } }, limit: 500 } }) });
  if (!q.ok) throw new Error("digest query " + q.status);
  const subs = (await q.json()).filter((x) => x.document).map((x) => ({ uid: x.document.name.split("/").pop(), prefs: fromDoc(x.document) }));
  if (!subs.length) { console.log(JSON.stringify({ type: "digest", subscribers: 0, sent: 0 })); return { sent: 0 }; }
  // current address and verification straight from Firebase Auth, never from stored data
  const lr = await fetch("https://identitytoolkit.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/accounts:lookup", { method: "POST", headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: JSON.stringify({ localId: subs.map((s) => s.uid) }) });
  const accts = new Map(((await lr.json().catch(() => ({}))).users || []).map((a) => [a.localId, a]));
  const kev = await loadKev();
  const now = Date.now(), out = [], sentUids = [];
  for (const s of subs) {
    const a = accts.get(s.uid);
    if (!a || a.disabled || !a.emailVerified || !a.email) continue;
    if (s.prefs.lastSent && now - s.prefs.lastSent < 5 * DAY) continue; // never twice in one week
    const url = await unsubUrl(env, s.uid);
    const d = buildDigest({ kev, prefs: s.prefs, now, unsubUrl: url });
    if (d.empty) continue;
    out.push(mail(env, a.email, s.uid, d, url)); sentUids.push(s);
  }
  for (let i = 0; i < out.length; i += 100) await resend(env, "/emails/batch", out.slice(i, i + 100));
  if (sentUids.length) {
    const writes = sentUids.map((s) => ({ update: { name: "projects/" + env.FIREBASE_PROJECT_ID + "/databases/(default)/documents/digest/" + s.uid, fields: toFields({ ...s.prefs, lastSent: now }) }, updateMask: { fieldPaths: ["json"] } }));
    await fetch(fsBase(env) + ":commit", { method: "POST", headers: { Authorization: "Bearer " + tok, "Content-Type": "application/json" }, body: JSON.stringify({ writes }) });
  }
  console.log(JSON.stringify({ type: "digest", subscribers: subs.length, sent: out.length }));
  return { subscribers: subs.length, sent: out.length };
}
