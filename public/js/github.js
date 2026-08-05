// GitHub integration for the web console. GitHub's REST API is CORS-enabled,
// so we can show a user's profile, repositories, and activity client-side.
// A token (stored only in the browser) unlocks private repos + higher rate limits.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const T_KEY = "sw_gh_token", U_KEY = "sw_gh_user";
const getTok = () => { try { return localStorage.getItem(T_KEY) || ""; } catch (_) { return ""; } };
const getUser = () => { try { return localStorage.getItem(U_KEY) || ""; } catch (_) { return ""; } };
const ago = (d) => { const s = (Date.now() - new Date(d)) / 1000; if (s < 3600) return Math.floor(s / 60) + "m ago"; if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago"; };

async function api(path, token) {
  const h = { Accept: "application/vnd.github+json" };
  if (token) h.Authorization = "Bearer " + token;
  const r = await fetch("https://api.github.com" + path, { headers: h });
  if (!r.ok) { const e = new Error(r.status === 403 ? "rate limit or forbidden (add a token)" : r.status === 404 ? "not found" : r.status + " " + r.statusText); e.status = r.status; throw e; }
  return r.json();
}

export function renderGitHub(main) {
  main.innerHTML = `
    <h1 class="pg-h1">GitHub</h1>
    <p class="muted pg-sub">Browse your profile, repositories, and recent activity. Add a token to see private repos and avoid rate limits.</p>
    <div class="card" style="max-width:680px">
      <div class="set-lbl">Connect</div>
      <div class="row" style="gap:8px;flex-wrap:wrap">
        <input class="tk-f" id="ghuser" placeholder="GitHub username" value="${esc(getUser())}" style="min-width:150px">
        <input class="tk-f" id="ghtoken" type="password" placeholder="token (optional)" value="${esc(getTok())}" style="min-width:150px">
        <button class="btn" id="ghgo">Connect</button>
        <button class="btn ghost" id="ghclear">Disconnect</button>
      </div>
      <p class="muted" style="font-size:.72rem;margin:8px 0 0">Your token stays in this browser only. A classic token with <code>repo</code> + <code>read:user</code> shows private repos. Leave the token blank to browse any public profile.</p>
    </div>
    <div id="ghout"></div>`;

  const $ = (sel) => main.querySelector(sel);
  const out = $("#ghout");

  function repoCard(r) {
    return `<a class="feed-card" href="${esc(r.html_url)}" target="_blank" rel="noopener">
      <div class="feed-top"><span class="feed-name">${esc(r.name)}</span>${r.private ? '<span class="chip">private</span>' : ""}</div>
      <div class="feed-desc">${esc(r.description || "No description")}</div>
      <div class="feed-meta"><span class="muted">${r.language ? esc(r.language) + " · " : ""}★ ${r.stargazers_count} · ⑂ ${r.forks_count}</span><span class="muted">${ago(r.updated_at)}</span></div>
    </a>`;
  }
  const eventText = (e) => {
    const repo = e.repo ? e.repo.name : "";
    const m = { PushEvent: "pushed to", CreateEvent: "created", WatchEvent: "starred", ForkEvent: "forked", PullRequestEvent: "PR on", IssuesEvent: "issue on", DeleteEvent: "deleted in" };
    return `${m[e.type] || e.type.replace("Event", "")} ${esc(repo)}`;
  };

  async function load() {
    const token = getTok(); let user = getUser();
    out.innerHTML = `<div class="muted" style="padding:14px">Loading…</div>`;
    try {
      const profile = user ? await api("/users/" + encodeURIComponent(user), token) : await api("/user", token);
      user = profile.login;
      const repos = await api((user && !token ? "/users/" + user + "/repos" : "/user/repos") + "?sort=updated&per_page=30", token).catch(() => []);
      const events = await api("/users/" + user + "/events/public?per_page=12", token).catch(() => []);
      out.innerHTML = `
        <div class="gh-profile card">
          <img class="gh-avatar" src="${esc(profile.avatar_url)}" alt="">
          <div class="gh-pinfo">
            <div class="gh-name">${esc(profile.name || profile.login)} <a class="link-btn" href="${esc(profile.html_url)}" target="_blank" rel="noopener">@${esc(profile.login)}</a></div>
            ${profile.bio ? `<div class="muted">${esc(profile.bio)}</div>` : ""}
            <div class="gh-stats">
              <span><strong>${profile.public_repos}</strong> repos</span>
              <span><strong>${profile.followers}</strong> followers</span>
              <span><strong>${profile.following}</strong> following</span>
            </div>
          </div>
        </div>
        <div class="home-cols">
          <div class="hc-main">
            <div class="panel-h"><h2 class="pg-h2" style="margin:0">Repositories</h2><span class="muted">${repos.length}${repos.length === 30 ? "+" : ""}</span></div>
            <div class="feed-grid">${repos.length ? repos.map(repoCard).join("") : '<p class="muted">No repositories.</p>'}</div>
          </div>
          <div class="hc-side">
            <div class="panel"><div class="panel-h"><h2 class="pg-h2" style="margin:0">Recent activity</h2></div>
              <div class="feed-list">${events.length ? events.map((e) => `<div class="feed-row"><span class="fr-name">${eventText(e)}</span><span class="fr-tag muted">${ago(e.created_at)}</span></div>`).join("") : '<p class="muted" style="font-size:.82rem">No public activity.</p>'}</div>
            </div>
          </div>
        </div>`;
    } catch (e) {
      out.innerHTML = `<div class="card" style="max-width:680px"><p class="bad">Couldn't load GitHub: ${esc(e.message)}.</p><p class="muted" style="font-size:.8rem">Enter a username, or add a token for private data and higher limits.</p></div>`;
    }
  }

  $("#ghgo").onclick = () => {
    try { localStorage.setItem(T_KEY, $("#ghtoken").value.trim()); localStorage.setItem(U_KEY, $("#ghuser").value.trim()); } catch (_) {}
    load();
  };
  $("#ghclear").onclick = () => {
    try { localStorage.removeItem(T_KEY); localStorage.removeItem(U_KEY); } catch (_) {}
    $("#ghtoken").value = ""; $("#ghuser").value = ""; out.innerHTML = "";
  };
  if (getUser() || getTok()) load();
}
