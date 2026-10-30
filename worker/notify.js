// Alert delivery (Deck D4). Builds the request body for each channel and posts it.
// Payload builders are PURE and unit-tested; deliver() does the one fetch. Works in the
// Cloudflare worker and in node (both have fetch + WebCrypto). No secrets live here —
// webhook URLs and signing secrets come from the workspace config at call time.
//
// Email is intentionally NOT implemented here: it needs an owner-chosen provider and a
// worker secret (an owner decision gate). Slack, Teams, Discord and signed webhooks all
// work with no provider, so monitoring alerts are useful before that decision is made.

import { hostAllowed } from "./net-guard.js";

const SEV_EMOJI = { critical: "red", high: "orange", medium: "blue", low: "grey", info: "grey" };

// A normalised alert: { title, severity, text, url?, workspace?, events?:[{kind,title,severity,detail}] }
function lines(alert) {
  const out = [];
  if (Array.isArray(alert.events)) for (const e of alert.events) out.push(`• [${String(e.severity || "").toUpperCase()}] ${e.title}${e.detail ? " — " + e.detail : ""}`);
  return out;
}

// Slack incoming webhook (also what Mattermost accepts).
export function slackPayload(alert) {
  const body = lines(alert);
  return {
    text: `*${alert.title}*`,
    blocks: [
      { type: "header", text: { type: "plain_text", text: alert.title.slice(0, 150) } },
      ...(alert.text ? [{ type: "section", text: { type: "mrkdwn", text: alert.text } }] : []),
      ...(body.length ? [{ type: "section", text: { type: "mrkdwn", text: body.join("\n").slice(0, 2900) } }] : []),
      ...(alert.url ? [{ type: "section", text: { type: "mrkdwn", text: `<${alert.url}|Open in the Deck>` } }] : []),
    ],
  };
}

// Microsoft Teams incoming webhook (MessageCard).
export function teamsPayload(alert) {
  const body = lines(alert);
  return {
    "@type": "MessageCard", "@context": "https://schema.org/extensions",
    summary: alert.title.slice(0, 150),
    themeColor: ({ critical: "C62828", high: "F5920B", medium: "2552C6", low: "8893A8", info: "8893A8" }[alert.severity] || "2552C6"),
    title: alert.title,
    text: [alert.text || "", body.join("\n\n")].filter(Boolean).join("\n\n").slice(0, 3000),
    potentialAction: alert.url ? [{ "@type": "OpenUri", name: "Open in the Deck", targets: [{ os: "default", uri: alert.url }] }] : undefined,
  };
}

// Discord incoming webhook (embeds).
export function discordPayload(alert) {
  const body = lines(alert);
  return {
    content: undefined,
    embeds: [{
      title: alert.title.slice(0, 250),
      description: [alert.text || "", body.join("\n")].filter(Boolean).join("\n").slice(0, 4000),
      color: ({ critical: 0xc62828, high: 0xf5920b, medium: 0x2552c6, low: 0x8893a8, info: 0x8893a8 }[alert.severity] || 0x2552c6),
      url: alert.url || undefined,
    }],
  };
}

// Generic JSON webhook body: the full alert, as sent (what the HMAC signs).
export function genericPayload(alert) {
  return { type: "darknode.alert", sentAt: new Date().toISOString(), alert };
}

const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

// HMAC-SHA256 of the exact request body string, hex. The receiver recomputes it over
// the raw body to verify authenticity. Async (WebCrypto).
export async function signBody(bodyStr, secret) {
  if (!secret) return "";
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(bodyStr)));
}

const BUILDERS = { slack: slackPayload, mattermost: slackPayload, teams: teamsPayload, discord: discordPayload, webhook: genericPayload };

// deliver(channel, alert, { fetch }) -> { ok, status, error? }
// channel: { type, url, secret? }. One POST, no retry here (the DO owns retry/backoff).
export async function deliver(channel, alert, deps = {}) {
  const f = deps.fetch || (typeof fetch !== "undefined" ? fetch : null);
  if (!f) return { ok: false, status: 0, error: "no fetch available" };
  if (!channel || !channel.url) return { ok: false, status: 0, error: "no channel url" };
  // SSRF guard: a workspace member sets channel.url, so re-validate it against the
  // same public-host allowlist as /api/fetch before we POST to it (blocks loopback,
  // RFC1918, link-local/cloud-metadata and numeric-encoded private addresses).
  let target;
  try { target = new URL(channel.url); } catch (_) { return { ok: false, status: 0, error: "invalid channel url" }; }
  if (!hostAllowed(target)) return { ok: false, status: 0, error: "channel url host is not allowed" };
  // own-property lookup: a type of "__proto__"/"hasOwnProperty" must not resolve to an
  // Object.prototype member (that threw, failing the whole alarm before it saved its run)
  const build = Object.hasOwn(BUILDERS, channel.type) ? BUILDERS[channel.type] : genericPayload;
  const bodyStr = JSON.stringify(build(alert));
  const headers = { "content-type": "application/json" };
  if (channel.type === "webhook" && channel.secret) {
    headers["x-darknode-signature"] = "sha256=" + (await signBody(bodyStr, channel.secret));
    headers["x-darknode-timestamp"] = String(Date.now());
  }
  try {
    // redirect:"manual": fetch follows redirects by default, so a public URL answering 307 would
    // carry this POST to a private host the guard above never saw. Webhooks don't redirect.
    const res = await f(target.href, { method: "POST", headers, body: bodyStr, redirect: "manual" });
    if (res.status >= 300 && res.status < 400) return { ok: false, status: res.status, error: "webhook answered with a redirect (" + res.status + "), which is not followed - use the final URL" };
    return { ok: res.ok, status: res.status };
  } catch (e) {
    return { ok: false, status: 0, error: e.message || String(e) };
  }
}

// Backoff schedule (ms) between delivery retries. Kept SHORT and bounded: the caller
// (_deliverWithRetry) awaits these inline on the request path and inside the alarm's
// blockConcurrencyWhile critical section, so a long sleep would hang the client response
// and freeze the whole workspace DO (risking an alarm-budget kill → re-invoke → duplicate
// alerts). Total worst-case stays ~3.5s/channel; durable long-delay retry belongs in an
// alarm-scheduled queue, not an inline sleep.
export const RETRY_BACKOFF_MS = [0, 500, 3000];
