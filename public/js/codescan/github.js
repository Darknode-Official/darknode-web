// Copyright (c) 2026 Darknode-Official. All rights reserved. See LICENSE.
// Code Scanner — GitHub + OSV.dev access, straight from the browser.
//
// The GitHub OAuth token lives ONLY in this module's memory for the current tab:
// it is never written to storage, Firestore, the Worker or logs. Public repos need
// no token at all (files come from raw.githubusercontent.com, which doesn't count
// against the API quota). api.github.com and api.osv.dev both allow CORS, so no
// proxy sits between the user and their code.

const API = "https://api.github.com";
let token = "";
let login = "";
export const rate = { remaining: null, limit: null, reset: null };

export const connected = () => !!token;
export const ghUser = () => login;
let kind = ""; // "pat" | "oauth"
export const tokenKind = () => (token ? kind : "");
export function disconnect() { token = ""; login = ""; kind = ""; }

// Connect GitHub through Firebase Auth with the `repo` scope (read access to the
// user's private repos). Signed-in users get GitHub linked to their account; a
// GitHub account already tied to another Darknode user still yields a token.
export async function connectGitHub() {
  const fa = await import("https://www.gstatic.com/firebasejs/12.17.0/firebase-auth.js");
  const { auth } = await import("/js/firebase.js?v=20261021a");
  const gh = new fa.GithubAuthProvider();
  gh.addScope("repo");
  gh.addScope("read:org");
  let res;
  try {
    const u = auth.currentUser;
    if (!u) res = await fa.signInWithPopup(auth, gh);
    else if (u.providerData.some((p) => p.providerId === "github.com")) res = await fa.reauthenticateWithPopup(u, gh);
    else res = await fa.linkWithPopup(u, gh);
  } catch (e) {
    const cred = e && e.code === "auth/credential-already-in-use" ? fa.GithubAuthProvider.credentialFromError(e) : null;
    if (!cred) throw new Error(e && e.code === "auth/popup-blocked" ? "The sign-in popup was blocked. Allow popups for this site and try again." : e && e.code === "auth/popup-closed-by-user" ? "GitHub sign-in was cancelled." : (e && e.message) || "GitHub sign-in failed.");
    res = { _cred: cred };
  }
  const cred = res._cred || fa.GithubAuthProvider.credentialFromResult(res);
  if (!cred || !cred.accessToken) throw new Error("GitHub did not return an access token.");
  token = cred.accessToken; kind = "oauth";
  const me = await api("/user");
  login = me.login || "";
  return login;
}

// Use a personal access token instead of OAuth (fine-grained, Contents: read-only).
export async function useToken(pat) {
  token = String(pat || "").trim(); kind = "pat";
  try { const me = await api("/user"); login = me.login || ""; return login; }
  catch (e) { token = ""; throw new Error("That token was rejected by GitHub: " + e.message); }
}

// Thrown errors carry `status` (HTTP code) and `rateLimited` so callers can react.
// The token only ever travels in the Authorization header, never in a URL.
export async function api(path, { raw = false, method = "GET", body } = {}) {
  const headers = { Accept: raw ? "application/vnd.github.raw" : "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" };
  if (token) headers.Authorization = "Bearer " + token;
  if (body !== undefined) headers["Content-Type"] = "application/json";
  let r;
  try { r = await fetch(path.startsWith("http") ? path : API + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) }); }
  catch (_) { throw new Error("Could not reach GitHub. Check your connection."); }
  const rem = r.headers.get("x-ratelimit-remaining");
  if (rem != null) { rate.remaining = +rem; rate.limit = +r.headers.get("x-ratelimit-limit"); rate.reset = +r.headers.get("x-ratelimit-reset") * 1000; }
  const fail = (msg, extra) => Object.assign(new Error(msg), { status: r.status }, extra);
  if (r.status === 404) throw fail(token ? "Not found, or your GitHub account has no access to it." : "Not found. If the repository is private, connect GitHub first.");
  if (r.status === 401) { token = ""; throw fail("GitHub rejected the session. Connect again."); }
  if (r.status === 403 || r.status === 429) {
    if (rate.remaining === 0) throw fail("GitHub API rate limit reached. It resets at " + new Date(rate.reset).toLocaleTimeString() + (token ? "." : ". Connecting GitHub raises the limit from 60 to 5,000 requests an hour."), { rateLimited: true });
    throw fail("GitHub refused the request (HTTP " + r.status + "). Your organization may need to approve the Darknode app.");
  }
  if (!r.ok) throw fail("GitHub returned HTTP " + r.status + ".");
  if (r.status === 204) return null;
  return raw ? r.text() : r.json();
}

// The signed-in user's repositories, most recently pushed first.
export async function listRepos() {
  const out = [];
  for (let page = 1; page <= 5; page++) {
    const batch = await api("/user/repos?per_page=100&sort=pushed&affiliation=owner,collaborator,organization_member&page=" + page);
    out.push(...batch.map((r) => ({ full: r.full_name, private: r.private, branch: r.default_branch, pushed: r.pushed_at, lang: r.language || "" })));
    if (batch.length < 100) break;
  }
  return out;
}

// Accept "owner/repo", a github.com URL, or ".../tree/<branch>".
export function parseRepo(input) {
  const s = String(input || "").trim().replace(/\.git$/, "").replace(/\/+$/, "");
  const m = s.match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+)(?:\/tree\/([^\s#?]+))?/i) || s.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
  return m ? { owner: m[1], repo: m[2], branch: m[3] || "" } : null;
}

// Repo metadata + the commit SHA we pin every file and link to.
export async function resolveRepo({ owner, repo, branch }) {
  const info = await api(`/repos/${owner}/${repo}`);
  const ref = branch || info.default_branch;
  const commit = await api(`/repos/${owner}/${repo}/commits/${encodeURIComponent(ref)}`);
  return { owner: info.owner.login, repo: info.name, full: info.full_name, private: info.private, branch: ref, sha: commit.sha, htmlUrl: info.html_url };
}

// Full file list. A truncated recursive tree (huge repos) falls back to walking
// sub-trees one level at a time.
export async function listFiles(r) {
  const t = await api(`/repos/${r.full}/git/trees/${r.sha}?recursive=1`);
  if (!t.truncated) return t.tree.filter((e) => e.type === "blob").map((e) => ({ path: e.path, size: e.size || 0 }));
  const files = [];
  const walk = async (sha, prefix, depth) => {
    const sub = await api(`/repos/${r.full}/git/trees/${sha}`);
    for (const e of sub.tree) {
      const p = prefix + e.path;
      if (e.type === "blob") files.push({ path: p, size: e.size || 0 });
      else if (e.type === "tree" && depth < 12 && !SKIP_DIR.test(p + "/")) await walk(e.sha, p + "/", depth + 1);
      if (files.length > 20000) return;
    }
  };
  await walk(r.sha, "", 0);
  return files;
}

export async function fileText(r, path) {
  const enc = path.split("/").map(encodeURIComponent).join("/");
  if (!r.private && !token) {
    const res = await fetch(`https://raw.githubusercontent.com/${r.full}/${r.sha}/${enc}`);
    if (!res.ok) throw new Error("HTTP " + res.status);
    return res.text();
  }
  return api(`/repos/${r.full}/contents/${enc}?ref=${r.sha}`, { raw: true });
}

// ── Which files are worth scanning ────────────────────────────────────────────
export const SKIP_DIR = /(^|\/)(node_modules|vendor|bower_components|dist|build|out|target|\.next|\.nuxt|coverage|\.git|__pycache__|\.venv|venv|site-packages|third_party|Pods)\//;
const BINARY = /\.(png|jpe?g|gif|webp|ico|bmp|tiff?|svg|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|war|class|exe|dll|so|dylib|bin|o|a|wasm|woff2?|ttf|otf|eot|mp[34]|mov|avi|webm|wav|ogg|psd|sketch|fig|sqlite|db|lock\.json\.gz)$/i;
const MINIFIED = /\.min\.(js|css)$|\.bundle\.js$|-bundle\.js$|\.map$/i;
export const MAX_FILE = 600 * 1024;

// .darknodeignore: gitignore-style paths a repository declares are not production
// code (reference data, fixtures, deliberately vulnerable samples). Supports comments,
// `dir/`, `*`, `?`, `**` and a leading `/` to anchor at the root; `!` lines are ignored.
export const IGNORE_FILE = ".darknodeignore";
export function ignoreMatcher(text) {
  const res = [];
  for (const raw of String(text || "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("!")) continue;
    let p = line.replace(/^\//, "");
    const dir = p.endsWith("/");
    if (dir) p = p.slice(0, -1);
    if (!p) continue;
    const anchored = line.startsWith("/") || p.includes("/");
    const body = p.split("**/").map((part) => part.split("**").map((q) => q.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]")).join(".*")).join("(?:.*/)?");
    res.push(new RegExp((anchored ? "^" : "(?:^|/)") + body + (dir ? "/" : "(?:/|$)")));
  }
  return { size: res.length, test: (path) => res.some((r) => r.test(path)) };
}

export function pickFiles(files, isManifest, cap = 1500) {
  const keep = files.filter((f) => !SKIP_DIR.test(f.path) && !BINARY.test(f.path) && !MINIFIED.test(f.path) && f.size <= MAX_FILE);
  const manifests = keep.filter((f) => isManifest(f.path));
  const rest = keep.filter((f) => !isManifest(f.path));
  // Prefer source and config over docs when we have to cap.
  const rank = (p) => /\.(js|mjs|cjs|ts|tsx|jsx|py|go|php|java|kt|rb|cs)$/i.test(p) ? 0 : /(^|\/)(Dockerfile|\.env[^/]*|[^/]+\.(ya?ml|tf|sh|json|toml|ini|cfg|conf|properties|xml))$/i.test(p) ? 1 : 2;
  rest.sort((a, b) => rank(a.path) - rank(b.path));
  const chosen = [...manifests, ...rest].slice(0, cap);
  return { chosen, skipped: files.length - chosen.length };
}

// ── OSV.dev (dependency advisories) ───────────────────────────────────────────
export async function osvQuery(deps) {
  const hits = [];
  for (let i = 0; i < deps.length; i += 500) {
    const chunk = deps.slice(i, i + 500);
    const r = await fetch("https://api.osv.dev/v1/querybatch", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })) }) });
    if (!r.ok) throw new Error("OSV.dev returned HTTP " + r.status + ".");
    const j = await r.json();
    (j.results || []).forEach((res, k) => { for (const v of (res && res.vulns) || []) hits.push({ dep: chunk[k], id: v.id }); });
  }
  return hits;
}
const vulnCache = new Map();
export async function osvVuln(id) {
  if (vulnCache.has(id)) return vulnCache.get(id);
  const p = fetch("https://api.osv.dev/v1/vulns/" + encodeURIComponent(id)).then((r) => (r.ok ? r.json() : null)).catch(() => null);
  vulnCache.set(id, p);
  return p;
}

// Run async jobs with bounded concurrency.
export async function pool(items, n, fn) {
  let i = 0;
  const run = async () => { while (i < items.length) { const k = i++; await fn(items[k], k); } };
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, run));
}
