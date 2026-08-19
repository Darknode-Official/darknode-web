// GitHub integration for the web console. GitHub's REST API is CORS-enabled,
// so we can show a user's profile, repositories, and activity client-side.
// A token (stored only in the browser) unlocks private repos + higher rate limits.
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const T_KEY = "sw_gh_token", U_KEY = "sw_gh_user";
const getTok = () => { try { return localStorage.getItem(T_KEY) || ""; } catch (_) { return ""; } };
const getUser = () => { try { return localStorage.getItem(U_KEY) || ""; } catch (_) { return ""; } };
const ago = (d) => { const s = (Date.now() - new Date(d)) / 1000; if (s < 3600) return Math.floor(s / 60) + "m ago"; if (s < 86400) return Math.floor(s / 3600) + "h ago"; return Math.floor(s / 86400) + "d ago"; };

// Hand text to the AI assistant: stash it, then open the AI section.
function askAI(text) {
  try { sessionStorage.setItem("sw_ai_prefill", text); } catch (_) {}
  const it = document.querySelector('.side-item[data-sec="ai"]'); if (it) it.click();
}
const ghB64 = (d) => { try { return decodeURIComponent(escape(atob(String(d || "").replace(/\n/g, "")))); } catch (_) { try { return atob(String(d || "").replace(/\n/g, "")); } catch (e) { return ""; } } };

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
      const prs = ((await api("/search/issues?q=" + encodeURIComponent("author:" + user + " is:pr is:open") + "&per_page=8", token).catch(() => ({ items: [] }))).items) || [];
      const issues = ((await api("/search/issues?q=" + encodeURIComponent("author:" + user + " is:issue is:open") + "&per_page=8", token).catch(() => ({ items: [] }))).items) || [];
      const issRow = (p) => `<a class="feed-row" href="${esc(p.html_url)}" target="_blank" rel="noopener"><span class="fr-id mono">#${p.number}</span><span class="fr-name">${esc(p.title)}</span></a>`;
      const gists = await api((user ? "/users/" + user + "/gists" : "/gists") + "?per_page=8", token).catch(() => []);
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
            <div class="panel"><div class="panel-h"><h2 class="pg-h2" style="margin:0">Open PRs</h2></div>
              <div class="feed-list">${prs.length ? prs.map(issRow).join("") : '<p class="muted" style="font-size:.82rem">None open.</p>'}</div>
            </div>
            <div class="panel"><div class="panel-h"><h2 class="pg-h2" style="margin:0">Open issues</h2></div>
              <div class="feed-list">${issues.length ? issues.map(issRow).join("") : '<p class="muted" style="font-size:.82rem">None open.</p>'}</div>
            </div>
            <div class="panel"><div class="panel-h"><h2 class="pg-h2" style="margin:0">Gists</h2></div>
              <div class="feed-list">${gists.length ? gists.map((g) => `<a class="feed-row" href="${esc(g.html_url)}" target="_blank" rel="noopener"><span class="fr-name">${esc(Object.keys(g.files || {})[0] || "gist")}</span><span class="fr-tag muted">${g.public ? "public" : "secret"}</span></a>`).join("") : '<p class="muted" style="font-size:.82rem">No gists.</p>'}</div>
            </div>
            <div class="panel"><div class="panel-h"><h2 class="pg-h2" style="margin:0">Recent activity</h2></div>
              <div class="feed-list">${events.length ? events.map((e) => `<div class="feed-row"><span class="fr-name">${eventText(e)}</span><span class="fr-tag muted">${ago(e.created_at)}</span></div>`).join("") : '<p class="muted" style="font-size:.82rem">No public activity.</p>'}</div>
            </div>
          </div>
        </div>
        <div class="card" style="max-width:680px;margin-top:16px">
          <div class="set-lbl">Create an issue</div>
          <div class="row" style="gap:8px;flex-wrap:wrap">
            <input class="tk-f" id="ci-repo" placeholder="owner/repo" style="min-width:160px" value="${repos[0] ? esc(repos[0].full_name) : ""}">
            <input class="tk-f" id="ci-title" placeholder="title" style="min-width:180px">
            <button class="btn" id="ci-go">Create</button>
          </div>
          <textarea class="tk-in" id="ci-body" rows="2" placeholder="description (optional)" style="margin-top:8px"></textarea>
          <p id="ci-msg" style="font-size:.8rem;margin:8px 0 0;min-height:1em"></p>
        </div>
        <div class="card" style="max-width:680px;margin-top:16px">
          <div class="set-lbl">Comment on an issue / PR</div>
          <div class="row" style="gap:8px;flex-wrap:wrap">
            <input class="tk-f" id="cc-repo" placeholder="owner/repo" style="min-width:160px" value="${repos[0] ? esc(repos[0].full_name) : ""}">
            <input class="tk-f" id="cc-num" placeholder="#" style="max-width:80px">
            <button class="btn" id="cc-go">Comment</button>
          </div>
          <textarea class="tk-in" id="cc-body" rows="2" placeholder="your comment" style="margin-top:8px"></textarea>
          <p id="cc-msg" style="font-size:.8rem;margin:8px 0 0;min-height:1em"></p>
        </div>
        <div class="card" style="max-width:840px;margin-top:16px">
          <div class="set-lbl">Browse a repo &amp; edit with AI</div>
          <div class="row" style="gap:8px;flex-wrap:wrap">
            <input class="tk-f" id="br-repo" placeholder="owner/repo" style="min-width:180px" value="${repos[0] ? esc(repos[0].full_name) : ""}">
            <input class="tk-f" id="br-path" placeholder="path (blank = root)" style="min-width:140px">
            <button class="btn" id="br-go">Open</button>
          </div>
          <div id="br-crumbs" class="muted mono" style="font-size:.78rem;margin:8px 0 0"></div>
          <div id="br-list" style="margin-top:8px"></div>
          <div id="br-view"></div>
        </div>`;
      // ---- repo browser + "edit with AI" ----
      const brRepo = () => out.querySelector("#br-repo").value.trim();
      async function brOpen(path) {
        const repo = brRepo(); const list = out.querySelector("#br-list"), view = out.querySelector("#br-view"), crumbs = out.querySelector("#br-crumbs");
        if (!repo.includes("/")) { list.innerHTML = `<p class="muted">enter owner/repo</p>`; return; }
        crumbs.textContent = repo + "/" + (path || ""); view.innerHTML = ""; list.innerHTML = `<p class="muted">loading…</p>`;
        try {
          const data = await api("/repos/" + repo + "/contents/" + encodeURIComponent(path || "").replace(/%2F/g, "/"), getTok());
          if (Array.isArray(data)) {
            const up = path ? `<div class="gh-row br-item" data-dir="${esc(path.split("/").slice(0, -1).join("/"))}" style="cursor:pointer"><span class="fr-name">📁 ..</span></div>` : "";
            const items = data.sort((a, b) => (a.type === b.type ? a.name.localeCompare(b.name) : a.type === "dir" ? -1 : 1));
            list.innerHTML = up + items.map((f) => `<div class="gh-row br-item" data-${f.type === "dir" ? "dir" : "file"}="${esc(f.path)}" style="cursor:pointer"><span class="fr-name">${f.type === "dir" ? "📁" : "📄"} ${esc(f.name)}</span></div>`).join("");
          } else if (data.content) {
            const body = ghB64(data.content);
            view.innerHTML = `<div class="card" style="margin-top:10px;background:var(--card2)">
              <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap"><b class="mono" style="font-size:.85rem">${esc(data.path)}</b><span class="muted" style="font-size:.75rem">${(data.size / 1024).toFixed(1)} KB</span></div>
              <pre class="mono" style="white-space:pre;overflow:auto;max-height:340px;margin:10px 0;font-size:.8rem">${esc(body).slice(0, 20000)}</pre>
              <div class="row" style="gap:8px;flex-wrap:wrap"><button class="btn" id="br-ai">Edit with AI</button><button class="btn ghost" id="br-explain">Explain with AI</button><a class="btn ghost" href="${esc(data.html_url)}" target="_blank" rel="noopener">Open on GitHub</a></div></div>`;
            view.querySelector("#br-ai").onclick = () => askAI("Here is `" + data.path + "` from the GitHub repo `" + repo + "`. Edit it as I ask and return the full updated file.\n\n```\n" + body.slice(0, 12000) + "\n```\n\nWhat I want changed: ");
            view.querySelector("#br-explain").onclick = () => askAI("Explain what this file (`" + data.path + "` from `" + repo + "`) does, and flag any bugs or security issues.\n\n```\n" + body.slice(0, 12000) + "\n```");
          }
        } catch (e2) { list.innerHTML = `<p class="bad">${esc(e2.message)}</p>`; }
      }
      out.querySelector("#br-go").onclick = () => brOpen(out.querySelector("#br-path").value.trim());
      out.querySelector("#br-list").onclick = (e2) => { const it = e2.target.closest(".br-item"); if (!it) return; if ("dir" in it.dataset) brOpen(it.dataset.dir); else if (it.dataset.file != null) brOpen(it.dataset.file); };
      out.querySelector("#cc-go").onclick = async () => {
        const t = getTok(), repo = out.querySelector("#cc-repo").value.trim(), num = out.querySelector("#cc-num").value.trim(), body = out.querySelector("#cc-body").value.trim(), msg = out.querySelector("#cc-msg");
        const set = (m, ok) => { msg.textContent = m; msg.style.color = ok ? "var(--ok)" : "var(--bad)"; };
        if (!t) return set("add a token to comment");
        if (!repo.includes("/") || !num || !body) return set("need owner/repo, #, and text");
        set("posting…", true);
        try {
          const r = await fetch("https://api.github.com/repos/" + repo + "/issues/" + num + "/comments", { method: "POST", headers: { Accept: "application/vnd.github+json", Authorization: "Bearer " + t, "Content-Type": "application/json" }, body: JSON.stringify({ body }) });
          if (!r.ok) throw new Error(r.status + " " + r.statusText);
          const d = await r.json();
          msg.innerHTML = 'posted <a href="' + esc(d.html_url) + '" target="_blank" rel="noopener" style="color:var(--acc)">comment</a>'; msg.style.color = "var(--ok)";
          out.querySelector("#cc-body").value = "";
        } catch (e2) { set(e2.message); }
      };
      const cig = out.querySelector("#ci-go");
      cig.onclick = async () => {
        const t = getTok(), repo = out.querySelector("#ci-repo").value.trim(), title = out.querySelector("#ci-title").value.trim(), msg = out.querySelector("#ci-msg");
        const set = (m, ok) => { msg.textContent = m; msg.style.color = ok ? "var(--ok)" : "var(--bad)"; };
        if (!t) return set("add a token above to create issues");
        if (!repo.includes("/") || !title) return set("need owner/repo and a title");
        set("creating…", true);
        try {
          const r = await fetch("https://api.github.com/repos/" + repo + "/issues", { method: "POST", headers: { Accept: "application/vnd.github+json", Authorization: "Bearer " + t, "Content-Type": "application/json" }, body: JSON.stringify({ title, body: out.querySelector("#ci-body").value }) });
          if (!r.ok) throw new Error(r.status + " " + r.statusText);
          const d = await r.json();
          msg.innerHTML = 'created <a href="' + esc(d.html_url) + '" target="_blank" rel="noopener" style="color:var(--acc)">#' + d.number + '</a>'; msg.style.color = "var(--ok)";
          out.querySelector("#ci-title").value = ""; out.querySelector("#ci-body").value = "";
        } catch (e2) { set(e2.message); }
      };
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
