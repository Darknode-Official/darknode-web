// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
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
.cb-wrap { font-family: ui-sans-serif, system-ui, -apple-system, sans-serif; color: #c8d6e5; max-width: 1200px; margin: 0 auto; }
.cb-source-note { background: #0a1628; border: 1px solid #1e3a5f; border-radius: 6px; padding: 10px 14px; font-size: 12px; line-height: 1.55; margin-bottom: 16px; color: #93b4d8; }
[data-style=pro] .cb-source-note { background: #f0f4ff; color: #1e3a5f; border-color: #dbeafe; }
.cb-header { display: flex; align-items: flex-start; justify-content: space-between; gap: 20px; margin-bottom: 24px; flex-wrap: wrap; }
.cb-header-left h1 { margin: 0 0 4px; font-size: 24px; font-family: 'JetBrains Mono', monospace; color: #fff; letter-spacing: 1px; }
.cb-header-left .cb-subtitle { color: #667788; font-size: 13px; font-family: 'JetBrains Mono', monospace; }
.cb-controls { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
.cb-select { background: #0d1420; border: 1px solid #1e2d44; color: #c8d6e5; padding: 7px 12px; border-radius: 6px; font-size: 12px; font-family: 'JetBrains Mono', monospace; cursor: pointer; appearance: none; -webkit-appearance: none; padding-right: 28px; background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M0 0l5 6 5-6z' fill='%23667788'/%3E%3C/svg%3E"); background-repeat: no-repeat; background-position: right 10px center; }
.cb-select:focus { outline: none; border-color: #3b82f6; }
.cb-btn { background: #1e293b; border: 1px solid #334155; color: #c8d6e5; padding: 7px 16px; border-radius: 6px; font-size: 12px; font-family: 'JetBrains Mono', monospace; cursor: pointer; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 6px; }
.cb-btn:hover { background: #334155; border-color: #475569; }
.cb-btn-primary { background: #1e40af; border-color: #2563eb; color: #fff; }
.cb-btn-primary:hover { background: #2563eb; }
.cb-section { background: linear-gradient(135deg, #0c1220, #0a0f1c); border: 1px solid #1a2540; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
.cb-section-title { color: #3b82f6; font-size: 13px; font-family: 'JetBrains Mono', monospace; letter-spacing: 2px; text-transform: uppercase; margin: 0 0 16px; padding-bottom: 10px; border-bottom: 1px solid #1a2540; display: flex; align-items: center; gap: 8px; }
.cb-section-sub { color: #667788; font-size: 11px; font-family: 'JetBrains Mono', monospace; margin: -10px 0 14px; }
.cb-bluf { background: #0a1628; border: 1px solid #1e3a5f; border-left: 4px solid #3b82f6; border-radius: 0 8px 8px 0; padding: 16px 20px; margin-bottom: 16px; }
.cb-bluf-label { color: #3b82f6; font-size: 11px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 2px; margin-bottom: 8px; }
.cb-bluf-text { font-size: 13px; line-height: 1.7; color: #d1dbe8; white-space: pre-line; }
.cb-table { width: 100%; border-collapse: collapse; font-size: 12px; font-family: 'JetBrains Mono', monospace; }
.cb-table th { text-align: left; padding: 10px 12px; color: #60a5fa; font-size: 10px; letter-spacing: 1.5px; text-transform: uppercase; border-bottom: 2px solid #1a2540; font-weight: 600; white-space: nowrap; }
.cb-table td { padding: 10px 12px; border-bottom: 1px solid #111d30; vertical-align: middle; }
.cb-table tbody tr { transition: background 0.15s ease; }
.cb-table tbody tr:hover { background: rgba(59, 130, 246, 0.06); }
.cb-ioc-type { font-size: 9px; font-family: 'JetBrains Mono', monospace; font-weight: 700; letter-spacing: 1px; padding: 2px 8px; border-radius: 3px; background: #1e293b; color: #93c5fd; white-space: nowrap; }
.cb-cve { color: #f59e0b; font-family: 'JetBrains Mono', monospace; font-weight: 600; }
.cb-ransom-yes { color: #ef4444; font-weight: 700; }
.cb-ransom-no { color: #667788; }
.cb-epss-bar-wrap { width: 90px; height: 6px; background: #111d30; border-radius: 3px; overflow: hidden; display: inline-block; vertical-align: middle; margin-right: 6px; }
.cb-epss-bar { height: 100%; border-radius: 3px; background: #ef4444; }
.cb-stats-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 16px; }
.cb-stat-card { background: #0a1220; border: 1px solid #1a2540; border-radius: 6px; padding: 12px; text-align: center; }
.cb-stat-value { font-size: 24px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }
.cb-stat-label { font-size: 10px; color: #667788; font-family: 'JetBrains Mono', monospace; letter-spacing: 1px; text-transform: uppercase; margin-top: 4px; }
.cb-empty { color: #667788; font-size: 12px; padding: 20px; text-align: center; }
.cb-err { background: #2a0a0a; border: 1px solid #dc2626; color: #fca5a5; border-radius: 8px; padding: 16px 20px; font-size: 13px; line-height: 1.6; }
.cb-loading { color: #667788; font-size: 13px; padding: 40px; text-align: center; font-family: 'JetBrains Mono', monospace; }
/* Export modal */
.cb-export-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 1000; display: flex; align-items: center; justify-content: center; }
.cb-export-modal { background: #0c1220; border: 1px solid #1a2540; border-radius: 12px; padding: 24px; max-width: 800px; width: 90%; max-height: 80vh; overflow-y: auto; }
.cb-export-textarea { width: 100%; min-height: 400px; background: #070d18; border: 1px solid #1a2540; color: #c8d6e5; font-family: 'JetBrains Mono', monospace; font-size: 11px; padding: 16px; border-radius: 6px; resize: vertical; }
.cb-export-actions { display: flex; gap: 10px; margin-top: 12px; justify-content: flex-end; }
@media (max-width: 768px) { .cb-header { flex-direction: column; } }
/* ── Pro Theme Overrides ── */
[data-style=pro] .cb-wrap { color: #3f3f46; }
[data-style=pro] .cb-header-left h1 { color: #18181b; }
[data-style=pro] .cb-header-left .cb-subtitle { color: #71717a; }
[data-style=pro] .cb-section { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-section-title { color: #2563eb; border-bottom-color: #e5e5e5; }
[data-style=pro] .cb-bluf { background: #f0f4ff; border-color: #dbeafe; border-left-color: #2563eb; }
[data-style=pro] .cb-bluf-text { color: #1e293b; }
[data-style=pro] .cb-select { background: #fff; border-color: #d4d4d8; color: #18181b; }
[data-style=pro] .cb-btn { background: #f4f4f5; border-color: #d4d4d8; color: #18181b; }
[data-style=pro] .cb-btn:hover { background: #e4e4e7; }
[data-style=pro] .cb-btn-primary { background: #2563eb; border-color: #2563eb; color: #fff; }
[data-style=pro] .cb-btn-primary:hover { background: #1d4ed8; }
[data-style=pro] .cb-table th { color: #2563eb; border-bottom-color: #e5e5e5; }
[data-style=pro] .cb-table td { border-bottom-color: #f4f4f5; }
[data-style=pro] .cb-table tbody tr:hover { background: rgba(37, 99, 235, 0.04); }
[data-style=pro] .cb-ioc-type { background: #f0f4ff; color: #2563eb; }
[data-style=pro] .cb-cve { color: #b45309; }
[data-style=pro] .cb-stat-card { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-stat-label { color: #71717a; }
[data-style=pro] .cb-export-modal { background: #fff; border-color: #e5e5e5; }
[data-style=pro] .cb-export-textarea { background: #fafafa; border-color: #e5e5e5; color: #18181b; }
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
  const kevData = await dnFetchJSON(KEV_URL, { timeout: 25000 });
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

  return { allKev, recentKev, epss, victims, victimsError, cutoff };
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

  let h = '<div class="cb-bluf">';
  h += '<div class="cb-bluf-label">BOTTOM LINE UP FRONT (BLUF)</div>';
  h += '<div class="cb-bluf-text">' + esc(text) + '</div>';
  h += '</div>';
  return h;
}

function renderStats(d, fig) {
  const stats = [
    { value: d.recentKev.length, label: 'KEV In Scope', color: '#ef4444' },
    { value: fig.ransomKev.length, label: 'Ransomware-Linked', color: '#dc2626' },
    { value: fig.topEpss ? fig.topEpss.pct.toFixed(0) + '%' : 'n/a', label: 'Top EPSS', color: '#f59e0b' },
    { value: d.victims.length, label: 'Recent Ransom Victims', color: '#ea580c' },
    { value: fig.groupCount, label: 'Active Groups', color: '#8b5cf6' },
    { value: d.allKev.length, label: 'KEV Catalog Total', color: '#3b82f6' }
  ];
  let h = '<div class="cb-stats-row">';
  stats.forEach(s => {
    h += '<div class="cb-stat-card"><div class="cb-stat-value" style="color:' + s.color + '">' + esc(String(s.value)) + '</div><div class="cb-stat-label">' + esc(s.label) + '</div></div>';
  });
  h += '</div>';
  return h;
}

function renderKevTable(d) {
  let h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9888;</span> Known-Exploited Vulnerabilities</div>';
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
    h += '<td>' + (ransom ? '<span class="cb-ransom-yes">KNOWN</span>' : '<span class="cb-ransom-no">—</span>') + '</td>';
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
  let h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9650;</span> Highest Exploitation Probability</div>';
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
  let h = '<div class="cb-section">';
  h += '<div class="cb-section-title"><span class="cb-icon">&#9673;</span> Recent Ransomware Victim Activity</div>';
  h += '<div class="cb-section-sub">Source: ransomware.live — organisations recently posted on ransomware leak sites.</div>';
  if (d.victimsError) { h += '<div class="cb-empty">Leak-site feed unavailable: ' + esc(d.victimsError) + '</div></div>'; return h; }
  if (!d.victims.length) { h += '<div class="cb-empty">No recent victims returned.</div></div>'; return h; }
  if (fig.topGroups.length) {
    h += '<div style="margin-bottom:12px;color:#8899aa;font-size:11px;font-family:\'JetBrains Mono\',monospace;">Most active groups: ';
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
  t += sep + '\nEXECUTIVE CYBER BRIEFING (LIVE)\n';
  t += 'Generated: ' + getNowISO() + '\n';
  t += 'Audience: ' + aud.label + '\n';
  t += 'Sources: CISA KEV catalog, FIRST EPSS, ransomware.live. Real data; not a drill.\n';
  t += sep + '\n\n';
  t += 'BOTTOM LINE UP FRONT\n' + line + '\n';
  t += aud.lead + '\n';
  t += '- KEV in scope: ' + d.recentKev.length + ' (catalog total ' + d.allKev.length + ')\n';
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
    let h = '<div class="cb-header"><div class="cb-header-left">';
    h += '<h1>EXECUTIVE CYBER BRIEFING</h1>';
    h += '<div class="cb-subtitle">Generated ' + esc(getNowISO()) + ' — live data from CISA KEV, FIRST EPSS and ransomware.live</div>';
    h += '</div><div class="cb-controls">';
    h += '<select class="cb-select" id="cb-audience">';
    AUDIENCES.forEach(a => { h += '<option value="' + esc(a.id) + '"' + (a.id === curAudience ? ' selected' : '') + '>' + esc(a.label) + '</option>'; });
    h += '</select>';
    h += '<button class="cb-btn" id="cb-refresh">&#8635; Refresh</button>';
    h += '<button class="cb-btn cb-btn-primary" id="cb-export">&#9660; Export</button>';
    h += '</div></div>';
    return h;
  }

  function bodyHtml() {
    if (loading) return '<div class="cb-loading">Assembling live briefing from CISA KEV, EPSS and ransomware.live…</div>';
    if (error) return '<div class="cb-err"><strong>Could not assemble the briefing.</strong><br>' + esc(error) + '<br><br>This briefing uses only live data; no fictional or cached scenario is shown in its place. Use Refresh to try again.</div>';
    if (!data) return '';
    let h = '';
    h += '<div class="cb-source-note">This is a real operational briefing built at load time from public threat sources. Figures reflect the live catalogs; nothing is simulated.</div>';
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
      '<div style="font-size:16px;font-weight:700;color:#e2e8f0">Export Briefing</div>' +
      '<button class="cb-btn" id="cb-export-close">&times; Close</button></div>' +
      '<textarea class="cb-export-textarea" id="cb-export-text" readonly></textarea>' +
      '<div class="cb-export-actions"><button class="cb-btn" id="cb-copy-text">Copy to Clipboard</button></div></div>';
    const ta = overlay.querySelector('#cb-export-text');
    ta.value = text;
    document.body.appendChild(overlay);
    overlay.querySelector('#cb-export-close').addEventListener('click', () => overlay.remove());
    overlay.addEventListener('click', e => { if (e.target === overlay) overlay.remove(); });
    overlay.querySelector('#cb-copy-text').addEventListener('click', function () {
      const btn = this;
      const done = () => { btn.textContent = 'Copied!'; setTimeout(() => { btn.textContent = 'Copy to Clipboard'; }, 2000); };
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(ta.value).then(done).catch(() => { ta.select(); try { document.execCommand('copy'); done(); } catch (_) {} });
        else { ta.select(); document.execCommand('copy'); done(); }
      } catch (_) {}
    });
  }

  draw();
  load();
}
