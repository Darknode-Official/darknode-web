// Darknode Project - CRUCIBLE :: Fusion Command
// Pillar: the LIVE threat-picture command surface for the active wargame.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Exports one render function; all data/engine/esc come from ctx.core.
//   renderFusion(container, ctx)   ctx = { go(tabId), toast, core }
// This module imports nothing from crucible-core directly (uses ctx.core).

export function renderFusion(container, ctx) {
  const core = ctx.core;
  const esc = core.esc;

  // -- scoped style (crf- prefix; 4px control radii; theme tokens only) -----
  const STYLE = `
  <style>
  .crf-wrap{width:100%;display:flex;flex-direction:column;gap:14px}
  .crf-banner{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;
    background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 16px}
  .crf-banner.live{border-color:var(--acc);box-shadow:inset 0 0 0 1px var(--acc)}
  .crf-camp{font-weight:800;font-size:1rem;letter-spacing:.02em;color:var(--txt)}
  .crf-meta{font-size:.74rem;color:var(--mut);margin-top:3px;display:flex;flex-wrap:wrap;gap:4px 12px}
  .crf-meta b{color:var(--txt);font-weight:700}
  .crf-live{display:inline-flex;align-items:center;gap:6px;font-size:.68rem;letter-spacing:.1em;
    text-transform:uppercase;color:var(--mut)}
  .crf-live .crf-pulse{width:8px;height:8px;border-radius:50%;background:#64748b}
  .crf-live.on .crf-pulse{background:#dc2626;animation:crf-blink 1.1s infinite}
  .crf-live.done .crf-pulse{background:#16a34a;animation:none}
  @keyframes crf-blink{0%,100%{opacity:1}50%{opacity:.25}}

  .crf-sect-h{display:flex;align-items:baseline;justify-content:space-between;gap:10px;margin:0 0 10px}
  .crf-sect-h h3{margin:0;font-size:.92rem}
  .crf-sect-h span{font-size:.7rem;color:var(--mut);letter-spacing:.05em}

  /* kill-chain ribbon */
  .crf-ribbon{display:flex;gap:4px;overflow-x:auto;padding-bottom:4px}
  .crf-seg{flex:1 0 auto;min-width:96px;border:1px solid var(--line);border-radius:4px;
    padding:8px 9px;background:var(--card);position:relative}
  .crf-seg-i{font-size:.6rem;color:var(--mut);letter-spacing:.08em}
  .crf-seg-n{font-size:.72rem;font-weight:700;color:var(--txt);margin-top:2px;line-height:1.2}
  .crf-seg-s{font-size:.58rem;letter-spacing:.08em;text-transform:uppercase;margin-top:6px;font-weight:700}
  .crf-seg.untouched{opacity:.72}.crf-seg.untouched .crf-seg-s{color:var(--mut)}
  .crf-seg.idle .crf-seg-s{color:var(--mut)}
  .crf-seg.reached{border-color:#dc2626;background:color-mix(in srgb,#dc2626 12%,var(--card))}
  .crf-seg.reached .crf-seg-s{color:#dc2626}
  .crf-seg.detected{border-color:#d97706;background:color-mix(in srgb,#d97706 12%,var(--card))}
  .crf-seg.detected .crf-seg-s{color:#d97706}
  .crf-seg.blocked{border-color:#16a34a;background:color-mix(in srgb,#16a34a 12%,var(--card))}
  .crf-seg.blocked .crf-seg-s{color:#16a34a}

  .crf-legend{display:flex;flex-wrap:wrap;gap:6px 16px;margin-top:10px;font-size:.68rem;color:var(--mut)}
  .crf-legend span{display:inline-flex;align-items:center;gap:6px}
  .crf-sw{width:11px;height:11px;border-radius:3px;border:1px solid var(--line)}
  .crf-sw.reached{background:#dc2626;border-color:#dc2626}
  .crf-sw.detected{background:#d97706;border-color:#d97706}
  .crf-sw.blocked{background:#16a34a;border-color:#16a34a}

  /* estate map */
  .crf-estate{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px}
  .crf-zone{border:1px solid var(--line);border-radius:8px;background:var(--card);padding:12px}
  .crf-zone-h{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:10px}
  .crf-zone-n{font-size:.8rem;font-weight:700;color:var(--txt)}
  .crf-zone-t{font-size:.6rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);
    border:1px solid var(--line);border-radius:3px;padding:1px 6px}
  .crf-assets{display:flex;flex-direction:column;gap:8px}
  .crf-asset{border:1px solid var(--line);border-radius:4px;padding:8px 10px;background:var(--bg)}
  .crf-asset-n{font-size:.76rem;font-weight:700;color:var(--txt);display:flex;align-items:center;
    justify-content:space-between;gap:8px}
  .crf-asset-i{font-size:.62rem;color:var(--mut);margin-top:2px}
  .crf-asset.touched{border-color:#dc2626;box-shadow:inset 3px 0 0 #dc2626}
  .crf-asset.detected{border-color:#d97706;box-shadow:inset 3px 0 0 #d97706}
  .crf-cj{font-size:.55rem;font-weight:700;letter-spacing:.08em;color:#d97706;
    border:1px solid #d97706;border-radius:3px;padding:1px 5px}
  .crf-adot{width:8px;height:8px;border-radius:50%;background:#64748b;flex:0 0 auto}
  .crf-asset.touched .crf-adot{background:#dc2626}
  .crf-asset.detected .crf-adot{background:#d97706}

  /* feed */
  .crf-feed{max-height:340px;overflow-y:auto;display:flex;flex-direction:column;gap:6px}
  .crf-row{display:grid;grid-template-columns:52px 1fr auto;gap:10px;align-items:center;
    border:1px solid var(--line);border-radius:4px;padding:8px 10px;background:var(--bg)}
  .crf-row-t{font-size:.66rem;color:var(--mut);font-variant-numeric:tabular-nums}
  .crf-row-m{min-width:0}
  .crf-row-tech{font-size:.76rem;font-weight:700;color:var(--txt)}
  .crf-row-sub{font-size:.64rem;color:var(--mut);margin-top:2px;
    white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
  .crf-row-r{display:flex;align-items:center;gap:8px;flex:0 0 auto}
  .crf-sev{font-size:.6rem;font-weight:800;letter-spacing:.08em;text-transform:uppercase}
  .crf-badge{font-size:.58rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;
    border:1px solid var(--line);border-radius:3px;padding:1px 6px;color:var(--mut)}
  .crf-badge.contained{border-color:#16a34a;color:#16a34a}
  .crf-empty{padding:34px 18px;text-align:center;color:var(--mut);font-size:.82rem}
  .crf-empty .cru-btn{margin-top:12px}
  .crf-kpi-crit .cru-kpi-n{color:#dc2626}.crf-kpi-warn .cru-kpi-n{color:#d97706}
  .crf-kpi-good .cru-kpi-n{color:#16a34a}

  /* rollup + attribution */
  .crf-two{display:grid;grid-template-columns:1fr 1fr;gap:14px}
  @media (max-width:820px){.crf-two{grid-template-columns:1fr}}
  .crf-sub-empty{color:var(--mut);font-size:.8rem;padding:18px 4px}
  .crf-roll-sect{margin-bottom:14px}.crf-roll-sect:last-child{margin-bottom:0}
  .crf-roll-h{font-size:.62rem;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin-bottom:8px}
  .crf-roll-row{display:grid;grid-template-columns:82px 1fr 28px;align-items:center;gap:8px;margin-bottom:5px}
  .crf-roll-l{font-size:.68rem}
  .crf-roll-bar{height:8px;border-radius:4px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden}
  .crf-roll-fill{display:block;height:100%;border-radius:4px}
  .crf-fill-critical{background:#dc2626}.crf-fill-high{background:#ea580c}
  .crf-fill-medium{background:#d97706}.crf-fill-low{background:#16a34a}
  .crf-roll-n{font-size:.72rem;font-weight:700;text-align:right;font-variant-numeric:tabular-nums}
  .crf-chips{display:flex;flex-wrap:wrap;gap:6px}
  .crf-chip{font-size:.66rem;padding:2px 8px;border:1px solid var(--line);border-radius:3px;color:var(--mut)}
  .crf-chip b{color:var(--txt)}
  .crf-tt{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:5px}
  .crf-tt li{display:flex;align-items:center;justify-content:space-between;gap:8px;font-size:.74rem;
    border:1px solid var(--line);border-radius:4px;padding:5px 9px;background:var(--bg)}
  .crf-tt-n{display:inline-flex;align-items:center;gap:6px;font-weight:600;min-width:0}
  .crf-tt-c{font-size:.66rem;color:var(--mut);flex:0 0 auto}
  .crf-attr-head{font-size:.72rem;color:var(--mut);margin-bottom:10px;line-height:1.5}
  .crf-attr-head b{color:var(--txt)}
  .crf-attr-list{display:flex;flex-direction:column;gap:8px}
  .crf-attr-row{border:1px solid var(--line);border-radius:4px;padding:8px 10px;background:var(--bg)}
  .crf-attr-row.lead{border-color:var(--acc);box-shadow:inset 0 0 0 1px var(--acc)}
  .crf-attr-top{display:flex;align-items:center;justify-content:space-between;gap:8px}
  .crf-attr-name{font-size:.78rem;font-weight:700;display:inline-flex;align-items:center;gap:6px}
  .crf-attr-eng{font-size:.55rem;font-weight:800;letter-spacing:.06em;color:#dc2626;
    border:1px solid #dc2626;border-radius:3px;padding:0 5px}
  .crf-attr-pct{font-size:.78rem;font-weight:800;font-variant-numeric:tabular-nums}
  .crf-attr-sub{font-size:.64rem;color:var(--mut);margin:3px 0 6px}
  .crf-attr-bar{height:6px;border-radius:3px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden}
  .crf-attr-fill{display:block;height:100%;border-radius:3px;background:var(--acc)}
  </style>`;

  container.innerHTML = STYLE +
    '<div class="crf-wrap">' +
      '<div id="crf-banner"></div>' +
      '<div class="cru-kpis" id="crf-kpis"></div>' +
      '<div class="cru-card">' +
        '<div class="crf-sect-h"><h3>Kill-Chain Ribbon</h3><span>ATT&amp;CK tactic progression</span></div>' +
        '<div class="crf-ribbon" id="crf-ribbon"></div>' +
        '<div class="crf-legend">' +
          '<span><i class="crf-sw"></i>Untouched</span>' +
          '<span><i class="crf-sw reached"></i>Reached (undetected)</span>' +
          '<span><i class="crf-sw detected"></i>Detected</span>' +
          '<span><i class="crf-sw blocked"></i>Blocked</span>' +
        '</div>' +
      '</div>' +
      '<div class="crf-two">' +
        '<div class="cru-card">' +
          '<div class="crf-sect-h"><h3>Detection Rollup</h3><span>Severity &middot; sensor &middot; targets</span></div>' +
          '<div id="crf-rollup"></div>' +
        '</div>' +
        '<div class="cru-card">' +
          '<div class="crf-sect-h"><h3>Threat Attribution</h3><span>Technique-overlap analytic</span></div>' +
          '<div id="crf-attrib"></div>' +
        '</div>' +
      '</div>' +
      '<div class="cru-card">' +
        '<div class="crf-sect-h"><h3>Estate Threat Map</h3><span>Zones by trust &middot; live asset status</span></div>' +
        '<div class="crf-estate" id="crf-estate"></div>' +
      '</div>' +
      '<div class="cru-card">' +
        '<div class="crf-sect-h"><h3>Live Alert &amp; Incident Feed</h3><span id="crf-feed-n"></span></div>' +
        '<div id="crf-feed"></div>' +
      '</div>' +
    '</div>';

  const $ = (id) => container.querySelector('#' + id);

  // -------------------------------- state helpers --------------------------
  function run() { return core.CRU.run; }

  function tacticState(r, tid) {
    if (!r) return 'idle';
    if (r.blockedTactics && r.blockedTactics[tid]) return 'blocked';
    if (r.alerts.some((a) => a.tactic === tid)) return 'detected';
    if (r.events.some((e) => e.tactic === tid && !e.blocked)) return 'reached';
    return 'untouched';
  }

  function assetState(r, aid) {
    if (!r) return 'clean';
    if (r.alerts.some((a) => a.assetId === aid)) return 'detected';
    if ((r.reached && r.reached.indexOf(aid) !== -1) || r.events.some((e) => e.assetId === aid && !e.blocked)) return 'touched';
    return 'clean';
  }

  // -------------------------------- renderers ------------------------------
  function renderBanner() {
    const r = run();
    const el = $('crf-banner');
    if (!el) return;
    if (!r) {
      el.className = 'crf-banner';
      el.innerHTML =
        '<div><div class="crf-camp">Standing Threat Picture</div>' +
        '<div class="crf-meta">No active wargame. The estate is quiet and all sensors are green.</div></div>' +
        '<button class="cru-btn" data-act="launch">Launch a wargame</button>';
      return;
    }
    const P = core.POSTURE[r.postureId] || { name: r.postureId };
    const camp = r.campaign || {};
    const live = r.done ? 'done' : 'on';
    const label = r.contained ? 'Contained' : (r.done ? 'Run ended' : 'Live');
    el.className = 'crf-banner live';
    el.innerHTML =
      '<div>' +
        '<div class="crf-camp">' + esc(camp.name || 'Campaign') + '</div>' +
        '<div class="crf-meta">' +
          '<span>Actor <b>' + esc(camp.actor || 'Unknown') + '</b></span>' +
          '<span>Posture <b>' + esc(P.name) + '</b></span>' +
          '<span>Sophistication <b>' + esc(String(camp.sophistication || '-')) + '/5</b></span>' +
          '<span>Clock <b>' + esc(String(r.clockMin || 0)) + 'm</b></span>' +
          '<span>Step <b>' + esc(String(r.cursor || 0)) + '/' + esc(String((camp.steps || []).length)) + '</b></span>' +
        '</div>' +
      '</div>' +
      '<div class="crf-live ' + live + '"><span class="crf-pulse"></span>' + esc(label) + '</div>';
  }

  function renderKpis() {
    const r = run();
    const el = $('crf-kpis');
    if (!el) return;
    let alerts = 0, tech = 0, mttd = '—', crown = 0, incidents = 0, contain = 'Standing', cCls = '';
    if (r) {
      const sc = core.scoreRun(r);
      alerts = r.alerts.length;
      tech = new Set(r.events.map((e) => e.techniqueId)).size;
      mttd = sc.mttdMin == null ? '—' : sc.mttdMin + 'm';
      crown = sc.crownHit.length;
      incidents = r.alerts.filter((a) => a.status !== 'contained').length;
      if (r.contained) { contain = 'Contained'; cCls = 'crf-kpi-good'; }
      else if (r.done) { contain = 'Uncontained'; cCls = 'crf-kpi-crit'; }
      else { contain = 'Active'; cCls = 'crf-kpi-warn'; }
    }
    const tile = (n, l, cls) =>
      '<div class="cru-kpi ' + (cls || '') + '"><div class="cru-kpi-n">' + esc(String(n)) +
      '</div><div class="cru-kpi-l">' + esc(l) + '</div></div>';
    el.innerHTML =
      tile(alerts, 'Total Alerts') +
      tile(tech, 'Techniques Observed') +
      tile(mttd, 'Mean Time to Detect') +
      tile(crown, 'Crown Jewels Touched', crown ? 'crf-kpi-crit' : '') +
      tile(incidents, 'Active Incidents', incidents ? 'crf-kpi-warn' : '') +
      tile(contain, 'Containment', cCls);
  }

  function renderRibbon() {
    const r = run();
    const el = $('crf-ribbon');
    if (!el) return;
    el.innerHTML = core.TACTICS.map((t, i) => {
      const st = tacticState(r, t.id);
      const label = st === 'idle' ? 'Idle' :
        st === 'untouched' ? 'Clear' :
        st === 'reached' ? 'Reached' :
        st === 'detected' ? 'Detected' : 'Blocked';
      return '<div class="crf-seg ' + st + '">' +
        '<div class="crf-seg-i">' + esc(String(i + 1).padStart(2, '0')) + '</div>' +
        '<div class="crf-seg-n">' + esc(t.name) + '</div>' +
        '<div class="crf-seg-s">' + esc(label) + '</div>' +
      '</div>';
    }).join('');
  }

  function renderEstate() {
    const r = run();
    const el = $('crf-estate');
    if (!el) return;
    const zones = core.ESTATE.zones.slice().sort((a, b) => a.trust - b.trust);
    const crown = core.ESTATE.crownJewels || [];
    el.innerHTML = zones.map((z) => {
      const assets = core.ESTATE.assets.filter((a) => a.zone === z.id);
      const rows = assets.map((a) => {
        const st = assetState(r, a.id);
        const isCj = crown.indexOf(a.id) !== -1;
        return '<div class="crf-asset ' + st + '">' +
          '<div class="crf-asset-n"><span>' + esc(a.name) + '</span>' +
            '<span style="display:inline-flex;align-items:center;gap:6px">' +
            (isCj ? '<span class="crf-cj">CROWN</span>' : '') +
            '<span class="crf-adot"></span></span>' +
          '</div>' +
          '<div class="crf-asset-i">' + esc(a.ip) + ' &middot; ' + esc(a.type) + ' &middot; ' + esc(a.os) + '</div>' +
        '</div>';
      }).join('') || '<div class="crf-asset-i">No assets</div>';
      return '<div class="crf-zone">' +
        '<div class="crf-zone-h"><span class="crf-zone-n">' + esc(z.name) + '</span>' +
        '<span class="crf-zone-t">Trust ' + esc(String(z.trust)) + '</span></div>' +
        '<div class="crf-assets">' + rows + '</div>' +
      '</div>';
    }).join('');
  }

  function renderFeed() {
    const r = run();
    const el = $('crf-feed');
    const nEl = $('crf-feed-n');
    if (!el) return;
    const alerts = r ? r.alerts : [];
    if (nEl) nEl.textContent = alerts.length + ' alert' + (alerts.length === 1 ? '' : 's');
    if (!alerts.length) {
      el.className = '';
      el.innerHTML = '<div class="crf-empty">' +
        (r ? 'No detections yet. Sensors are watching the estate.'
           : 'No active run. Launch a wargame to light up the threat picture.') +
        (r ? '' : '<div><button class="cru-btn" data-act="launch">Launch a wargame</button></div>') +
        '</div>';
      return;
    }
    el.className = 'crf-feed';
    el.innerHTML = alerts.slice().reverse().map((a) => {
      const sev = 'cru-sev-' + (a.severity || 'low');
      const tac = (core.TECH[a.techniqueId] || {}).tactic || a.tactic || '';
      const tacName = ((core.TACTICS.find((t) => t.id === tac) || {}).name) || tac;
      return '<div class="crf-row">' +
        '<div class="crf-row-t">' + esc(String(a.t)) + 'm</div>' +
        '<div class="crf-row-m">' +
          '<div class="crf-row-tech">' + esc(a.techniqueId) + ' &middot; ' + esc(a.techniqueName) + '</div>' +
          '<div class="crf-row-sub">' + esc(tacName) + ' &rarr; ' + esc(a.assetName) +
            ' &middot; ' + esc(a.sensor) + (a.detection ? ' (' + esc(a.detection) + ')' : '') + '</div>' +
        '</div>' +
        '<div class="crf-row-r">' +
          '<span class="crf-sev ' + sev + '">' + esc(a.severity || 'low') + '</span>' +
          '<span class="crf-badge ' + (a.status === 'contained' ? 'contained' : '') + '">' +
            esc(a.status || 'new') + '</span>' +
        '</div>' +
      '</div>';
    }).join('');
  }

  // Severity rollup, sensor breakdown and the most-targeted assets, computed
  // live over the run's detections and events.
  function renderRollup() {
    const r = run();
    const el = $('crf-rollup');
    if (!el) return;
    if (!r || !r.alerts.length) {
      el.innerHTML = '<div class="crf-sub-empty">' +
        (r ? 'No detections yet. Rollups populate as sensors fire.' : 'No active run.') + '</div>';
      return;
    }
    const order = ['critical', 'high', 'medium', 'low'];
    const sevCount = {};
    r.alerts.forEach((a) => { const s = a.severity || 'low'; sevCount[s] = (sevCount[s] || 0) + 1; });
    const total = r.alerts.length;
    const sevBars = order.filter((s) => sevCount[s]).map((s) => {
      const n = sevCount[s], pct = Math.round(n / total * 100);
      return '<div class="crf-roll-row">' +
        '<span class="crf-roll-l"><span class="crf-sev cru-sev-' + s + '">' + esc(s) + '</span></span>' +
        '<span class="crf-roll-bar"><span class="crf-roll-fill crf-fill-' + s + '" style="width:' + pct + '%"></span></span>' +
        '<span class="crf-roll-n">' + esc(n) + '</span>' +
      '</div>';
    }).join('');

    // sensor breakdown
    const senCount = {};
    r.alerts.forEach((a) => { const s = a.sensor || 'Unknown'; senCount[s] = (senCount[s] || 0) + 1; });
    const senChips = Object.keys(senCount).sort((a, b) => senCount[b] - senCount[a]).slice(0, 6)
      .map((s) => '<span class="crf-chip">' + esc(s) + ' <b>' + esc(senCount[s]) + '</b></span>').join('');

    // most-targeted assets (by attacker events, alerted or not)
    const crown = core.ESTATE.crownJewels || [];
    const tgt = {};
    r.events.forEach((e) => { tgt[e.assetId] = (tgt[e.assetId] || 0) + 1; });
    const topTargets = Object.keys(tgt).sort((a, b) => tgt[b] - tgt[a]).slice(0, 5).map((id) => {
      const a = core.ASSET[id] || { name: id };
      const cj = crown.indexOf(id) !== -1;
      return '<li><span class="crf-tt-n">' + esc(a.name) + (cj ? ' <span class="crf-cj">CROWN</span>' : '') + '</span>' +
        '<span class="crf-tt-c">' + esc(tgt[id]) + ' hit' + (tgt[id] === 1 ? '' : 's') + '</span></li>';
    }).join('');

    el.innerHTML =
      '<div class="crf-roll-sect"><div class="crf-roll-h">By severity</div>' + sevBars + '</div>' +
      '<div class="crf-roll-sect"><div class="crf-roll-h">By sensor</div><div class="crf-chips">' + senChips + '</div></div>' +
      '<div class="crf-roll-sect"><div class="crf-roll-h">Most-targeted assets</div><ul class="crf-tt">' + topTargets + '</ul></div>';
  }

  // Behavioural attribution: rank every known adversary campaign by how much
  // its technique repertoire overlaps the techniques observed this run
  // (Jaccard similarity). The live campaign rises as its kill chain unfolds.
  function renderAttribution() {
    const r = run();
    const el = $('crf-attrib');
    if (!el) return;
    if (!r) { el.innerHTML = '<div class="crf-sub-empty">No active run to attribute.</div>'; return; }
    const observed = new Set(r.events.map((e) => e.techniqueId));
    if (!observed.size) {
      el.innerHTML = '<div class="crf-sub-empty">Awaiting telemetry. Attribution needs observed techniques.</div>';
      return;
    }
    const ranked = (core.CAMPAIGNS || []).map((c) => {
      const set = new Set((c.steps || []).map((s) => s.techniqueId));
      let inter = 0;
      observed.forEach((t) => { if (set.has(t)) inter += 1; });
      const union = new Set([...observed, ...set]).size;
      const sim = union ? inter / union : 0;
      return { c: c, inter: inter, size: set.size, sim: sim };
    }).sort((a, b) => b.sim - a.sim);

    const top = ranked[0];
    const isLive = top && r.campaignId === top.c.id;
    const rows = ranked.map((x, i) => {
      const pct = Math.round(x.sim * 100);
      const engaged = r.campaignId === x.c.id;
      return '<div class="crf-attr-row' + (i === 0 ? ' lead' : '') + '">' +
        '<div class="crf-attr-top">' +
          '<span class="crf-attr-name">' + esc(x.c.name) +
            (engaged ? ' <span class="crf-attr-eng">ENGAGED</span>' : '') + '</span>' +
          '<span class="crf-attr-pct">' + esc(pct) + '%</span>' +
        '</div>' +
        '<div class="crf-attr-sub">' + esc(x.c.actor) + ' &middot; ' + esc(x.inter) + '/' + esc(x.size) + ' techniques matched</div>' +
        '<div class="crf-attr-bar"><span class="crf-attr-fill" style="width:' + pct + '%"></span></div>' +
      '</div>';
    }).join('');
    const head = top
      ? '<div class="crf-attr-head">Leading candidate <b>' + esc(top.c.name) + '</b> (' + esc(top.c.actor) + ') at ' +
          esc(Math.round(top.sim * 100)) + '% overlap' + (isLive ? ' — consistent with the engaged campaign.' : '.') + '</div>'
      : '';
    el.innerHTML = head + '<div class="crf-attr-list">' + rows + '</div>';
  }

  function renderAll() {
    if (!container.isConnected) return;
    renderBanner();
    renderKpis();
    renderRibbon();
    renderRollup();
    renderAttribution();
    renderEstate();
    renderFeed();
  }

  // -------------------------------- wiring ---------------------------------
  container.addEventListener('click', (e) => {
    const btn = e.target.closest('[data-act]');
    if (btn && btn.getAttribute('data-act') === 'launch') ctx.go('range');
  });

  const onAny = () => { if (container.isConnected) renderAll(); };
  const subs = [
    core.on('event', onAny),
    core.on('alert', onAny),
    core.on('action', onAny),
    core.on('contained', onAny),
  ];

  let cleaned = false;
  function cleanup() {
    if (cleaned) return;
    cleaned = true;
    subs.forEach((u) => { try { u(); } catch (_) {} });
    clearInterval(poll);
  }
  const poll = setInterval(() => { if (!container.isConnected) cleanup(); }, 1500);

  renderAll();
}
