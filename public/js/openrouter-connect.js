// ============================================================================
// OpenRouter — genuine one-click "connect your account" (OAuth 2.0 PKCE).
//
// OpenRouter is the one AI provider that offers a real browser account-link:
// the user logs in to OpenRouter and approves, and the flow mints a USER-OWNED
// API key billed to *their* OpenRouter credits (not a shared Darknode key).
// Its PKCE flow needs NO client secret, so the whole handshake runs here in the
// browser — no backend/Worker changes. On success we store the minted key as
// dn_key_openrouter and mark OpenRouter connected in the DarkDeck store; webai.js
// already streams from both (OAI_COMPAT.openrouter).
//
// This is the honest alternative to "log in with your Claude/ChatGPT account":
// those consumer subscriptions cannot be driven by a third-party site, but one
// OpenRouter login reaches Claude/GPT/Gemini/Llama on the user's own balance —
// and OpenRouter has free (:free) models, so it can cost $0.
//   startOpenRouterConnect()      -> redirects to OpenRouter consent
//   completeOpenRouterConnect()   -> finishes the handshake on return (boot)
//   shouldReopenDeck()            -> one-shot: should DarkDeck re-open after return
// ============================================================================

const PKCE_LS = "dn_or_pkce";        // {verifier, state, ts} pending exchange
const REOPEN_LS = "dn_or_reopen";    // "1" -> re-open DarkDeck after returning
const CONN_LS = "dn_deck_connections_v1";
const AUTH_URL = "https://openrouter.ai/auth";
const EXCHANGE_URL = "https://openrouter.ai/api/v1/auth/keys";
const FREE_MODEL = "deepseek/deepseek-chat-v3-0324:free"; // default: no spend

function b64url(buf) {
  const a = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < a.length; i++) s += String.fromCharCode(a[i]);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function randToken(bytes) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return b64url(a); }
async function challengeOf(verifier) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return b64url(d);
}
function toastErr(m) { try { window.showToast && window.showToast(m, "error"); } catch (_) {} }

// Kick off the connect: mint PKCE params, stash them, full-page redirect to
// OpenRouter. The user returns to this exact page (callback_url) with ?code.
export async function startOpenRouterConnect() {
  if (!(window.crypto && crypto.subtle && location.protocol === "https:")) {
    toastErr("Secure connect needs HTTPS — open the deployed site to link OpenRouter.");
    return;
  }
  const verifier = randToken(48);
  const state = randToken(16);
  const challenge = await challengeOf(verifier);
  try {
    localStorage.setItem(PKCE_LS, JSON.stringify({ verifier, state, ts: Date.now() }));
    localStorage.setItem(REOPEN_LS, "1");
  } catch (_) {}
  const callback = location.origin + location.pathname; // return here (admin page -> DarkDeck)
  const url = AUTH_URL +
    "?callback_url=" + encodeURIComponent(callback) +
    "&code_challenge=" + encodeURIComponent(challenge) +
    "&code_challenge_method=S256" +
    "&state=" + encodeURIComponent(state);
  location.href = url;
}

// Run once on boot. If we came back from OpenRouter with ?code, exchange it for
// the user's key and persist the connection. Returns {done, ok?}. Always strips
// ?code from the URL so a reload can't replay a single-use code.
export async function completeOpenRouterConnect() {
  let code = null, state = null;
  try { const q = new URLSearchParams(location.search); code = q.get("code"); state = q.get("state"); } catch (_) {}
  if (!code) return { done: false };
  let pend = null; try { pend = JSON.parse(localStorage.getItem(PKCE_LS) || "null"); } catch (_) {}
  try { history.replaceState(null, "", location.origin + location.pathname); } catch (_) {}
  if (!pend || !pend.verifier) return { done: false };
  try { localStorage.removeItem(PKCE_LS); } catch (_) {}
  if (pend.state && state && pend.state !== state) { toastErr("OpenRouter connect failed (state mismatch)."); return { done: true, ok: false }; }
  if (pend.ts && Date.now() - pend.ts > 11 * 60 * 1000) { toastErr("OpenRouter connect expired — please try again."); return { done: true, ok: false }; }
  try {
    const r = await fetch(EXCHANGE_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code, code_verifier: pend.verifier, code_challenge_method: "S256" }),
    });
    const data = await r.json().catch(() => ({}));
    const key = data && data.key;
    if (!r.ok || !key) {
      const msg = data && data.error ? (data.error.message || data.error) : "";
      toastErr("OpenRouter connect failed" + (msg ? ": " + msg : "."));
      return { done: true, ok: false };
    }
    try {
      window.dnKeys.set("dn_key_openrouter", String(key).trim()); // per account (user-keys.js)
      const conns = JSON.parse(localStorage.getItem(CONN_LS) || "{}") || {};
      conns.openrouter = { connected: true, method: "account", hasKey: true, at: Date.now() };
      localStorage.setItem(CONN_LS, JSON.stringify(conns));
      // Default to a free model so a fresh connect costs nothing until they choose otherwise.
      if (!(localStorage.getItem("dn_model_openrouter") || "").trim()) localStorage.setItem("dn_model_openrouter", FREE_MODEL);
    } catch (_) {}
    try { window.showToast && window.showToast("OpenRouter account connected — pick a model in the deck", "success"); } catch (_) {}
    return { done: true, ok: true };
  } catch (_) {
    toastErr("OpenRouter connect failed (network).");
    return { done: true, ok: false };
  }
}

// One-shot flag: after returning from OpenRouter, DarkDeck should re-open so the
// user lands back where they started and sees the connection.
export function shouldReopenDeck() {
  try { if (localStorage.getItem(REOPEN_LS) === "1") { localStorage.removeItem(REOPEN_LS); return true; } } catch (_) {}
  return false;
}
