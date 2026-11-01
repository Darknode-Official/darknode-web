// Copyright (c) 2026 Darknode-Official. All rights reserved.
// Executive Cyber Briefing — a REAL threat briefing assembled live from public,
// keyless sources through the Darknode proxy:
//   - CISA Known Exploited Vulnerabilities catalog (cisa.gov): what is being
//     exploited in the wild right now, including ransomware-linked CVEs.
//   - FIRST EPSS (api.first.org): exploitation-probability scores for those CVEs.
//   - ransomware.live: organisations recently posted on ransomware leak sites.
// Nothing here is a canned APT narrative, a fictional inject, or a random value;
// every figure and row is derived from the fetched data and labelled with its
// source. If a source cannot be reached, an honest error is shown instead.
import { dnFetchJSON, proxyConfigured } from "/js/net.js";
import { loadKevCatalog } from "/js/core/kev-feed.js?v=20261101a";

const esc = (s) => String(s != null ? s : "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]);

const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const RANSOM_URL = "https://api.ransomware.live/v2/recentvictims";
const EPSS_URL = "https://api.first.org/data/v1/epss?cve=";

// Audience changes only the FRAMING LINE of the BLUF; the underlying facts are
// identical real data for every audience.
const AUDIENCES = [
  { id: 'ciso', label: 'CISO / Security Team', lead: 'Defensive priorities based on what is actively being exploited.' },
  { id: 'exec', label: 'Executive / Board', lead: 'Business-risk view of current, real-world exploitation and extortion activity.' },
  { id: 'soc', label: 'SOC / Threat Hunter', lead: 'Hunt and patch priorities drawn from live exploitation and leak-site telemetry.' },
  { id: 'isac', label: 'Sector ISAC', lead: 'Shared situational awareness for collective defence.' }
];

// ═══════════════════════════════════════════════════════════════════════════════
// STYLE BLOCK
// ═══════════════════════════════════════════════════════════════════════════════
function injectStyles() {
  if (document.getElementById('cb-styles')) return;
  const style = document.createElement('style');
  style.id = 'cb-styles';
  style.textContent = `
/* ── Cyber Briefing Generator ── */
.cb-wrap { color: var(--txt); }
.cb-source-note { color: var(--mut); font-size: 12px; margin-bottom: 12px; }
.cb-controls { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }
.cb-section { margin-bottom: 16px; }
.cb-section-title { color: var(--txt); font-size: 14px; font-weight: 600; margin: 0 0 6px; }
.cb-section-sub { color: var(--mut); font-size: 12px; margin: 0 0 12px; }
.cb-bluf { border-left: 3px solid var(--acc); margin-bottom: 16px; }
.cb-bluf-label { color: var(--txt); font-size: 14px; font-weight: 600; margin-bottom: 8px; }
.cb-bluf-text { font-size: 13px; line-height: 1.7; color: var(--txt-2, var(--txt)); white-space: pre-line; }
.cb-table { width: 100%; border-collapse: collapse; font-size: 12px; }
.cb-table th { text-align: left; padding: 8px 10px; color: var(--mut); font-size: 12px; border-bottom: 1px solid var(--line); font-weight: 600; white-space: nowrap; }
.cb-table td { padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: middle; }
.cb-ioc-type { font-size: 12px; padding: 1px 8px; border-radius: 4px; background: var(--card2); color: var(--txt-2, var(--txt)); white-space: nowrap; }
.cb-cve { color: var(--acc); font-family: var(--mono, monospace); font-weight: 600; }
.cb-ransom-yes { color: var(--bad); font-weight: 600; }
.cb-ransom-no { color: var(--mut); }
.cb-epss-bar-wrap { width: 90px; height: 6px; background: var(--line); border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 6px; }
.cb-epss-bar { height: 100%; border-radius: 3px; background: var(--bad); }
.cb-stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 16px; }
.cb-stat-card { text-align: center; }
.cb-stat-value { font-size: 24px; font-weight: 700; }
.cb-stat-label { font-size: 12px; color: var(--mut); margin-top: 4px; }
.cb-empty { color: var(--mut); font-size: 12px; padding: 20px; text-align: center; }
.cb-err { color: var(--bad); font-size: 13px; line-height: 1.6; }
.cb-loading { color: var(--mut); font-size: 13px; padding: 40px; text-align: center; }
/* Export modal */
.cb-export-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 1000; display: flex; align-items: center; justify-content: center; }
.cb-export-modal { background: var(--card); border: 1px solid var(--line); border-radius: 12px; padding: 24px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
.cb-export-textarea { width: 100%; min-height: 400px; font-family: var(--mono, monospace); font-size: 12px; padding: 12px; resize: vertical; }
.cb-export-actions { display: flex; gap: 8px; margin-top: 12px; justify-content: flex-end; }
`;
  document.head.appendChild(style);
}

// ═══════════════════════════════════════════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════════════════════════════════════════
function getNowISO() { return new Date().toISOString().replace('T', ' ').slice(0, 19) + 'Z'; }

function daysAgoISODate(days) {
  return new Date(Date.now() - days * 86400000).toISOString().slice(0, 10);
}

function epssPct(v) {
  var n = parseFloat(v);
  if (!isFinite(n)) return null;
  return n * 100;
}

// ═══════════════════════════════════════════════════════════════════════════════
// DATA ASSEMBLY (all real)
// ═══════════════════════════════════════════════════════════════════════════════
async function assembleBriefing() {
  const kevData = await loadKevCatalog();
  const allKev = (kevData && kevData.vulnerabilities) || [];
  const cutoff = daysAgoISODate(30);
  let recentKev = allKev.filter(v => String(v.dateAdded || "") >= cutoff);
  // If the last 30 days are sparse, fall back to the newest 40 additions so the
  // briefing is never empty when the catalog clearly has data.
  if (recentKev.length < 10) {
    recentKev = allKev.slice().sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || ""))).slice(0, 40);
  }
  recentKev.sort((a, b) => String(b.dateAdded || "").localeCompare(String(a.dateAdded || "")));

  // EPSS for the recent KEV CVEs (bulk, one request, capped at 100 ids).
  const epss = {};
  const ids = recentKev.map(v => v.cveID).filter(Boolean).slice(0, 100);
  if (ids.length) {
    try {
      const er = await dnFetchJSON(EPSS_URL + encodeURIComponent(ids.join(",")), { timeout: 25000 });
      ((er && er.data) || []).forEach(d => { if (d && d.cve) epss[d.cve] = epssPct(d.epss); });
    } catch (_) { /* EPSS is enrichment; its absence is not fatal */ }
  }

  // Ransomware leak-site recent victims.
  let victims = [];
  let victimsError = "";
  try {
    const vr = await dnFetchJSON(RANSOM_URL, { timeout: 25000 });
    victims = Array.isArray(vr) ? vr : [];
  } catch (err) {
    victimsError = String((err && err.message) || err);
  }

  return { allKev, kevTotal: kevData.count || allKev.length, recentKev, epss, victims, victimsError, cutoff };
}

// ═══════════════════════════════════════════════════════════════════════════════
// COMPUTED FIGURES
// ═══════════════════════════════════════════════════════════════════════════════
function computeFigures(d) {
  const ransomKev = d.recentKev.filter(v => v.knownRansomwareCampaignUse === "Known");
  let topEpss = null;
  d.recentKev.forEach(v => {
    const p = d.epss[v.cveID];
    if (p != null && (!topEpss || p > topEpss.pct)) topEpss = { cve: v.cveID, pct: p };
  });
  const groupCounts = {};
  d.victims.forEach(v => { if (v.group) groupCounts[v.group] = (groupCounts[v.group] || 0) + 1; });
  const topGroups = Object.keys(groupCounts).map(g => [g, groupCounts[g]]).sort((a, b) => b[1] - a[1]);
  return { ransomKev, topEpss, topGroups, groupCount: Object.keys(groupCounts).length };
}

// ═══════════════════════════════════════════════════════════════════════════════
// RENDERERS
// ═══════════════════════════════════════════════════════════════════════════════
function renderBLUF(d, fig, audience) {
  const aud = AUDIENCES.find(a => a.id === audience) || AUDIENCES[0];
  let text = aud.lead + "\n\n";
  text += "- " + d.recentKev.length + " vulnerabilities are currently in scope from the CISA Known Exploited Vulnerabilities catalog"
    + (String(d.recentKev[0] && d.recentKev[0].dateAdded) >= d.cutoff ? " (additions in the last 30 days)" : " (most recent additions)") + ".\n";
  text += "- " + fig.ransomKev.length + " of those are documented in known ransomware campaigns.\n";
  if (fig.topEpss) text += "- Highest exploitation probability (EPSS) among them: " + esc(fig.topEpss.cve) + " at " + fig.topEpss.pct.toFixed(1) + "%.\n";
  if (d.victims.length) {
    text += "- " + d.victims.length + " organisations were recently posted on ransomware leak sites across " + fig.groupCount + " groups";
    if (fig.topGroups.length) text += " (most active: " + esc(fig.topGroups[0][0]) + ", " + fig.topGroups[0][1] + " victims)";
    text += ".\n";
  } else if (d.victimsError) {
    text += "- Ransomware leak-site feed was unavailable this cycle (" + esc(d.victimsError) + ").\n";
  }
  text += "\nPriority action: patch or mitigate the known-exploited vulnerabilities below, prioritising ransomware-linked and high-EPSS CVEs.";

  let h = '<div class="card cb-bluf">';
  h += '<div class="cb-bluf-label">Bottom line up front</div>';
  h += '<div class="cb-bluf-text">' + esc(text) + '</div>';
  h += '</div>';
  return h;
}

function renderStats(d, fig) {
  const stats = [
    { value: d.recentKev.length, label: 'KEV in scope', color: 'var(--bad)' },
    { value: fig.ransomKev.length, label: 'Ransomware-linked', color: 'var(--bad)' },
    { value: fig.topEpss ? fig.topEpss.pct.toFixed(0) + '%' : 'n/a', label: 'Top EPSS', color: 'var(--warn)' },
    { value: d.victims.length, label: 'Recent leak-site posts', color: 'var(--warn)' },
    { value: fig.groupCount, label: 'Groups posting', color: 'var(--acc)' },
    { value: d.kevTotal || d.allKev.length, label: 'KEV catalog total', color: 'var(--acc)' }
  ];
  let h = '<div class="cb-stats-row">';
  stats.forEach(s => {
    h += '<div class="card cb-stat-card"><div class="cb-stat-value" style="color:' + s.color + '">' + esc(String(s.value)) + '</div><div class="cb-stat-label">' + esc(s.label) + '</div></div>';
  });
  h += '</div>';
  return h;
}

function renderKevTable(d) {
  let h = '<div class="card cb-section">';
  h += '<div class="cb-section-title">Known-exploited vulnerabilities</div>';
  h += '<div class="cb-section-sub">Source: CISA KEV catalog. EPSS exploitation probability from FIRST (api.first.org).</div>';
  if (!d.recentKev.length) { h += '<div class="cb-empty">No entries.</div></div>'; return h; }
  h += '<div style="overflow-x:auto"><table class="cb-table"><thead><tr><th>CVE</th><th>Vendor / Product</th><th>Vulnerability</th><th>Added</th><th>Ransomware</th><th>EPSS</th></tr></thead><tbody>';
  d.recentKev.slice(0, 60).forEach(v => {
    const ransom = v.knownRansomwareCampaignUse === "Known";
    const p = d.epss[v.cveID];
    h += '<tr>';
    h += '<td><span class="cb-cve">' + esc(v.cveID || '') + '</span></td>';
    h += '<td>' + esc([v.vendorProject, v.product].filter(Boolean).join(' / ')) + '</td>';
    h += '<td>' + esc(String(v.vulnerabilityName || '').substring(0, 90)) + '</td>';
    h += '<td>' + esc(v.dateAdded || '') + '</td>';
    h += '<td>' + (ransom ? '<span class="cb-ransom-yes">Known</span>' : '<span class="cb-ransom-no">—</span>') + '</td>';
    if (p != null) h += '<td><span class="cb-epss-bar-wrap"><span class="cb-epss-bar" style="width:' + Math.max(2, Math.min(100, p)) + '%"></span></span>' + p.toFixed(1) + '%</td>';
    else h += '<td class="cb-ransom-no">n/a</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div></div>';
  return h;
}

function renderEpssTop(d) {
  const ranked = d.recentKev
    .map(v => ({ cve: v.cveID, p: d.epss[v.cveID], name: v.vulnerabilityName, vp: [v.vendorProject, v.product].filter(Boolean).join(' / ') }))
    .filter(x => x.p != null)
    .sort((a, b) => b.p - a.p)
    .slice(0, 10);
  if (!ranked.length) return '';
  let h = '<div class="card cb-section">';
  h += '<div class="cb-section-title">Highest exploitation probability</div>';
  h += '<div class="cb-section-sub">Known-exploited CVEs ranked by EPSS score (likelihood of exploitation in the next 30 days).</div>';
  h += '<div style="overflow-x:auto"><table class="cb-table"><thead><tr><th>Rank</th><th>CVE</th><th>Vendor / Product</th><th>EPSS</th></tr></thead><tbody>';
  ranked.forEach((x, i) => {
    h += '<tr><td>' + (i + 1) + '</td><td><span class="cb-cve">' + esc(x.cve) + '</span></td><td>' + esc(x.vp) + '</td>';
    h += '<td><span class="cb-epss-bar-wrap"><span class="cb-epss-bar" style="width:' + Math.max(2, Math.min(100, x.p)) + '%"></span></span>' + x.p.toFixed(1) + '%</td></tr>';
  });
  h += '</tbody></table></div></div>';
  return h;
}

function renderVictims(d, fig) {
  let h = '<div class="card cb-section">';
  h += '<div class="cb-section-title">Recent ransomware leak-site posts</div>';
  h += '<div class="cb-section-sub">Source: ransomware.live — organisations recently posted on ransomware leak sites.</div>';
  if (d.victimsError) { h += '<div class="cb-empty">Leak-site feed unavailable: ' + esc(d.victimsError) + '</div></div>'; return h; }
  if (!d.victims.length) { h += '<div class="cb-empty">No recent victims returned.</div></div>'; return h; }
  if (fig.topGroups.length) {
    h += '<div style="margin-bottom:12px;color:var(--mut);font-size:12px;">Most active groups: ';
    h += fig.topGroups.slice(0, 6).map(g => esc(g[0]) + ' (' + g[1] + ')').join(' · ');
    h += '</div>';
  }
  h += '<div style="overflow-x:auto"><table class="cb-table"><thead><tr><th>Victim</th><th>Group</th><th>Sector</th><th>Country</th><th>Discovered</th></tr></thead><tbody>';
  d.victims.slice(0, 30).forEach(v => {
    h += '<tr>';
    h += '<td>' + esc(String(v.victim || '').substring(0, 60)) + '</td>';
    h += '<td><span class="cb-ioc-type">' + esc(v.group || '?') + '</span></td>';
    h += '<td>' + esc(v.activity || '') + '</td>';
    h += '<td>' + esc(v.country || '') + '</td>';
    h += '<td>' + esc(String(v.discovered || v.attackdate || '').replace('T', ' ').substring(0, 16)) + '</td>';
    h += '</tr>';
  });
  h += '</tbody></table></div></div>';
  return h;
}

// ═══════════════════════════════════════════════════════════════════════════════
// EXPORT
// ═══════════════════════════════════════════════════════════════════════════════
function generateExportText(d, fig, audience) {
  const aud = AUDIENCES.find(a => a.id === audience) || AUDIENCES[0];
  const sep = '='.repeat(72);
  const line = '-'.repeat(72);
  let t = '';
  t += sep + '\nEXECUTIVE CYBER BRIEFING\n';
  t += 'Generated: ' + getNowISO() + '\n';
  t += 'Audience: ' + aud.label + '\n';
  t += 'Sources: CISA KEV catalog, FIRST EPSS, ransomware.live.\n';
  t += sep + '\n\n';
  t += 'BOTTOM LINE UP FRONT\n' + line + '\n';
  t += aud.lead + '\n';
  t += '- KEV in scope: ' + d.recentKev.length + ' (catalog total ' + (d.kevTotal || d.allKev.length) + ')\n';
  t += '- Ransomware-linked: ' + fig.ransomKev.length + '\n';
  if (fig.topEpss) t += '- Highest EPSS: ' + fig.topEpss.cve + ' (' + fig.topEpss.pct.toFixed(1) + '%)\n';
  t += '- Recent ransomware victims: ' + d.victims.length + ' across ' + fig.groupCount + ' groups\n\n';

  t += 'KNOWN-EXPLOITED VULNERABILITIES\n' + line + '\n';
  d.recentKev.slice(0, 60).forEach(v => {
    const p = d.epss[v.cveID];
    t += (v.cveID || '') + ' | ' + [v.vendorProject, v.product].filter(Boolean).join(' / ') + ' | added ' + (v.dateAdded || '')
      + (v.knownRansomwareCampaignUse === 'Known' ? ' | RANSOMWARE' : '') + (p != null ? ' | EPSS ' + p.toFixed(1) + '%' : '') + '\n';
    if (v.vulnerabilityName) t += '  ' + v.vulnerabilityName + '\n';
  });
  t += '\n';

  if (d.victims.length) {
    t += 'RECENT RANSOMWARE VICTIMS\n' + line + '\n';
    d.victims.slice(0, 30).forEach(v => {
      t += (v.victim || '') + ' | ' + (v.group || '?') + ' | ' + (v.activity || '') + ' | ' + (v.country || '')
        + ' | ' + String(v.discovered || v.attackdate || '').replace('T', ' ').substring(0, 16) + '\n';
    });
    t += '\n';
  }
  t += sep + '\nEND OF BRIEFING\n';
  return t;
}

// ═══════════════════════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════════════════════
export function renderCyberBriefing(container) {
  injectStyles();

  let curAudience = 'ciso';
  let data = null;
  let figures = null;
  let loading = false;
  let error = '';

  function controlsHtml() {
    let h = '<div class="pg-head"><div>';
    h += '<h1 class="pg-h1">Cyber Briefing</h1>';
    h += '<p class="muted pg-sub">Executive briefing built when the page loads from CISA KEV, FIRST EPSS and ransomware.live. Generated ' + esc(getNowISO()) + '</p>';
    h += '</div><div class="cb-controls">';
    h += '<select class="cb-select" id="cb-audience">';
    AUDIENCES.forEach(a => { h += '<option value="' + esc(a.id) + '"' + (a.id === curAudience ? ' selected' : '') + '>' + esc(a.label) + '</option>'; });
    h += '</select>';
    h += '<button class="btn ghost" id="cb-refresh">Refresh</button>';
    h += '<button class="btn" id="cb-export">Export</button>';
    h += '</div></div>';
    return h;
  }

  function bodyHtml() {
    if (loading) return '<div class="cb-loading">Assembling live briefing from CISA KEV, EPSS and ransomware.live…</div>';
    if (error) return '<div class="card cb-err"><strong>Could not assemble the briefing.</strong><br>' + esc(error) + '<br><br>Use Refresh to try again.</div>';
    if (!data) return '';
    let h = '';
        h += renderBLUF(data, figures, curAudience);
    h += renderStats(data, figures);
    h += renderEpssTop(data);
    h += renderKevTable(data);
    h += renderVictims(data, figures);
    return h;
  }

  function draw() {
    container.innerHTML = '<div class="cb-wrap">' + controlsHtml() + bodyHtml() + '</div>';
    wire();
  }

  function wire() {
    const aud = container.querySelector('#cb-audience');
    const refresh = container.querySelector('#cb-refresh');
    const exportBtn = container.querySelector('#cb-export');
    if (aud) aud.addEventListener('change', function () { curAudience = this.value; draw(); });
    if (refresh) refresh.addEventListener('click', load);
    if (exportBtn) exportBtn.addEventListener('click', showExport);
  }

  async function load() {
    if (loading) return;
    if (!proxyConfigured()) { error = 'The Darknode proxy is not configured, so the live threat sources cannot be reached.'; data = null; draw(); return; }
    loading = true; error = ''; draw();
    try {
      data = await assembleBriefing();
      figures = computeFigures(data);
    } catch (err) {
      error = String((err && err.message) || err);
      data = null;
    } finally {
      loading = false;
      draw();
    }
  }

  function showExport() {
    if (!data) return;
    const text = generateExportText(data, figures, curAudience);
    const overlay = document.createElement('div');
    overlay.className = 'cb-export-overlay';
    overlay.innerHTML = '<div class="cb-export-modal">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">' +
      '<div style="font-size:16px;font-weight:600;color:var(--txt)">Export briefing</div>' +
      '<button class="btn ghost" id="cb-export-close">Close</button></div>' +
      '<textarea class="cb-export-textarea" id="cb-export-text" readonly></textarea>' +
      '<div class="cb-export-actions"><button class="btn" id="cb-copy-text">Copy to clipboard</button></div></div>';
    const ta = overlay.querySelector('#cb-export-text');
    ta.value = text;
    document.body.appendChild(overlay);
    overlay.querySelector('#cb-export-close').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector('#cb-copy-text').addEventListener('click', function () {
      const btn = this;
      const done = () => { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy to clipboard'; }, 2000); };
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(ta.value).then(done).catch(() => { ta.select(); try { document.execCommand('copy'); done(); } catch (_) {} });
        else { ta.select(); document.execCommand('copy'); done(); }
      } catch (_) {}
    });
  }

  draw();
  load();
}
