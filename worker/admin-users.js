// GET /api/admin/users (owner only, role "admin" in the route table): every Firebase Auth
// account, read with the Worker's service account. The admin panel lists Firestore users/{uid}
// docs, and an email sign-up that never verifies never writes one, so those accounts were
// invisible there. Only the fields the panel shows are returned.
import { googleToken } from "./digest.js";

export function authUserRow(u) {
  return {
    uid: u.localId,
    email: u.email || "",
    name: u.displayName || "",
    emailVerified: !!u.emailVerified,
    disabled: !!u.disabled,
    providers: (u.providerUserInfo || []).map((p) => String(p.providerId || "").replace(/\.com$/, "")).filter(Boolean),
    createdAt: Number(u.createdAt) || null,
    lastLoginAt: Number(u.lastLoginAt) || null,
  };
}

export async function handleAdminUsers(env, json, opts = {}) {
  if (!env.FIREBASE_PROJECT_ID) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const doFetch = opts.fetch || fetch;
  let token;
  try { token = await (opts.token || googleToken)(env); }
  catch (e) { return json({ error: "Server credentials unavailable: " + e.message }, 503); }
  const users = [];
  let next = "";
  for (let page = 0; page < 20; page++) { // 20 x 1000 accounts
    const url = "https://identitytoolkit.googleapis.com/v1/projects/" + env.FIREBASE_PROJECT_ID + "/accounts:batchGet?maxResults=1000" + (next ? "&nextPageToken=" + encodeURIComponent(next) : "");
    const r = await doFetch(url, { headers: { Authorization: "Bearer " + token } });
    if (!r.ok) return json({ error: "Firebase Auth listing failed (HTTP " + r.status + ")." }, 502);
    const d = await r.json().catch(() => ({}));
    for (const u of d.users || []) users.push(authUserRow(u));
    next = d.nextPageToken || "";
    if (!next) break;
  }
  return json({ users, truncated: !!next });
}
