// Admin panel: who uses Nexus, the desktop app and the app's virtual machines.
// Reads usage/{uid} (written by the Worker from signed-in heartbeats; owner-only in the
// rules). Pure helpers are exported for tests; render() draws into the admin panel.

export const PRODUCTS = [
  { key: "nexus", label: "Nexus" },
  { key: "app", label: "Desktop app" },
  { key: "vm", label: "VMs" },
];
const DAY = 864e5;

const msOf = (v) => (v && v.toMillis ? v.toMillis() : v && v.toDate ? v.toDate().getTime() : typeof v === "number" ? v : v ? Date.parse(v) || 0 : 0);

// docs: [{ uid, email, nexus?, app?, vm? }] -> rows for one product, most recent first
export function usageRows(docs, product) {
  return (docs || [])
    .filter((d) => d && d[product] && msOf(d[product].last))
    .map((d) => {
      const p = d[product];
      return {
        uid: d.uid, email: d.email || "", last: msOf(p.last), first: msOf(p.first),
        version: p.version || "", os: p.os || "",
        count: Number(p.count) || 0, running: Number(p.running) || 0, pings: Number(p.pings) || 0,
      };
    })
    .sort((a, b) => b.last - a.last);
}

// -> { nexus: { total, week }, app: {...}, vm: {...} }  (week = seen in the last 7 days)
export function usageSummary(docs, now = Date.now()) {
  const out = {};
  for (const { key } of PRODUCTS) {
    const rows = usageRows(docs, key);
    out[key] = { total: rows.length, week: rows.filter((r) => now - r.last < 7 * DAY).length };
  }
  return out;
}

const OS = { linux: "Linux", darwin: "macOS", win32: "Windows" };
export const osLabel = (o) => OS[o] || "";

export function ago(ms, now = Date.now()) {
  if (!ms) return "never";
  const s = Math.max(0, Math.round((now - ms) / 1000));
  if (s < 90) return "just now";
  if (s < 3600) return Math.round(s / 60) + " min ago";
  if (s < 86400) return Math.round(s / 3600) + " h ago";
  if (s < 30 * 86400) return Math.round(s / 86400) + " d ago";
  return new Date(ms).toLocaleDateString();
}

// host: the panel body; docs: usage docs; state: { tab, q }; esc: the panel's HTML escaper
export function render(host, docs, state, esc, now = Date.now()) {
  const sum = usageSummary(docs, now);
  const tabs = PRODUCTS.map((p) => `<button class="btn ${state.tab === p.key ? "" : "ghost "}sm" data-utab="${p.key}">${esc(p.label)} <span class="muted">${sum[p.key].total}</span></button>`).join("");
  const q = (state.q || "").toLowerCase().trim();
  const rows = usageRows(docs, state.tab).filter((r) => !q || (r.email + " " + r.uid).toLowerCase().includes(q));
  const label = PRODUCTS.find((p) => p.key === state.tab).label;
  const s = sum[state.tab];
  const head = `<p class="muted" style="font-size:.82rem;margin:8px 0">${s.total} ${s.total === 1 ? "person has" : "people have"} used ${esc(label)} while signed in; ${s.week} in the last 7 days.</p>`;
  const list = rows.length
    ? rows.map((r) => {
        const detail = state.tab === "vm"
          ? `${r.count} VM${r.count === 1 ? "" : "s"}${r.running ? ` · ${r.running} running` : ""}`
          : [r.version && "v" + r.version, osLabel(r.os)].filter(Boolean).join(" · ");
        return `<div class="user-row"><div class="ur-main"><div class="ur-name">${esc(r.email || r.uid)}</div>
          <div class="ur-meta muted">${esc(detail || "—")} · first seen ${esc(r.first ? new Date(r.first).toLocaleDateString() : "—")}</div></div>
          <div class="ur-seen muted" title="${esc(new Date(r.last).toLocaleString())}">${esc(ago(r.last, now))}</div></div>`;
      }).join("")
    : `<p class="muted" style="font-size:.82rem">${q ? "No matching people." : "No one yet. Nexus reports once someone signs in to it; the desktop app and its VMs report from version 2.55.4."}</p>`;
  host.innerHTML = `<div style="display:flex;gap:6px;flex-wrap:wrap">${tabs}</div>${head}${list}`;
}
