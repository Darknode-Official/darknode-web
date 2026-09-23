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

  function renderAll() {
    if (!container.isConnected) return;
    renderBanner();
    renderKpis();
    renderRibbon();
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
