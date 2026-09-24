// Darknode Project - CRUCIBLE :: Defense Autopilot
// Pillar: an autonomous blue-team AI that watches the active wargame run,
// reasons over each detection and races the attacker to containment.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Exports exactly: renderAutopilot(container, ctx)
//   ctx = { go(tabId), toast(msg,kind), core }  (core = crucible-core exports)
// All data / engine / escaping comes from ctx.core. This file imports nothing.

export function renderAutopilot(container, ctx) {
  const core = ctx.core;
  const esc = core.esc;
  const CJ = core.ESTATE.crownJewels;
  const sevMap = { critical: 5, high: 4, medium: 3, low: 2, low0: 1 };

  // --- per-render lifecycle bookkeeping ------------------------------------
  const subs = [];        // unsubscribe fns from core.on(...)
  const timers = [];      // setTimeout / setInterval ids
  const processed = new Set();   // alert ids the agent has already picked up
  const pending = new Map();     // alertId -> { actionIds, applied, decideEl }
  const monitored = new Map();   // alertId -> { entry, decision, priority } held below policy threshold
  let ticker = null;      // interval that drives the attacker forward
  let torn = false;

  // Current autonomous-containment policy (aggressiveness preset from core).
  function policy() {
    return (core.AGGRESSION && core.AGGRESSION[core.CRU.aggressiveness]) ||
      (core.AGGRESSIONS && core.AGGRESSIONS[1]) ||
      { id: 'balanced', name: 'Balanced', threshold: 6, maxActions: 2 };
  }

  function teardown() {
    if (torn) return;
    torn = true;
    subs.forEach((u) => { try { u(); } catch (_) {} });
    timers.forEach((t) => { clearTimeout(t); clearInterval(t); });
    subs.length = 0; timers.length = 0;
  }
  function later(fn, ms) { const t = setTimeout(() => { if (!alive()) return; fn(); }, ms); timers.push(t); return t; }
  function alive() { if (!container.isConnected) { teardown(); return false; } return true; }

  // Poll for disconnect so we always release the event-bus subscriptions.
  const watch = setInterval(() => { if (!container.isConnected) { clearInterval(watch); teardown(); } }, 1000);
  timers.push(watch);

  // -------------------------------------------------------------------------
  const run = core.CRU.run;
  if (!run) { renderEmpty(); return; }

  renderShell();
  wireControls();
  // Reason over alerts already sitting on the run, staggered so it streams.
  const existing = run.alerts.slice();
  existing.forEach((al, i) => later(() => ingest(al, true), 200 + i * 550));
  // And subscribe to everything the engine emits from here on.
  subs.push(core.on('alert', (al) => { if (alive()) ingest(al, false); }));
  subs.push(core.on('action', () => { if (alive()) { renderStatus(); renderKpis(); renderPolicy(); } }));
  subs.push(core.on('contained', () => { stopTicker(); if (alive()) { renderStatus(); renderKpis(); renderBanner(); renderPolicy(); ctx.toast('Threat contained by autopilot', 'good'); } }));
  subs.push(core.on('event', () => { if (alive()) { renderBanner(); renderPolicy(); } }));

  // Race the attacker: while the run is live, Autopilot itself drives the
  // campaign one step at a time so alerts arrive in real time and the agent
  // can block the remaining tactics before the objective is reached. If the
  // run is already finished when we open (retrospective), we do not step.
  startTicker();

  function startTicker() {
    if (ticker || !run || run.done || run.contained) return;
    ticker = setInterval(() => {
      if (!alive()) { stopTicker(); return; }
      if (run.done || run.contained) { stopTicker(); if (alive()) renderBanner(); return; }
      core.stepRun(run); // emits event/alert -> our handlers reason + contain
    }, 700);
    timers.push(ticker);
  }
  function stopTicker() { if (ticker) { clearInterval(ticker); ticker = null; } }

  // ======================= EMPTY STATE =====================================
  function renderEmpty() {
    container.innerHTML =
      styleBlock() +
      '<div class="cru-card cra-empty">' +
        '<h3>No active engagement</h3>' +
        '<p class="cru-sub">The Defense Autopilot needs a live wargame run to defend. Launch an adversary campaign on the Wargame Range, then return here and the autonomous blue team will take over.</p>' +
        '<div class="cra-row"><button class="cru-btn" id="cra-go-range">Go to Wargame Range</button></div>' +
      '</div>';
    const b = container.querySelector('#cra-go-range');
    if (b) b.onclick = () => ctx.go('range');
  }

  // ======================= SHELL / LAYOUT ==================================
  function renderShell() {
    container.innerHTML =
      styleBlock() +
      '<div class="cra-topbar">' +
        '<div>' +
          '<h3 style="margin:0;font-size:1rem">Defense Autopilot</h3>' +
          '<p class="cru-sub" style="margin:2px 0 0">Autonomous blue-team agent defending <strong>' + esc(assetsLabel()) + '</strong> against <strong>' + esc(run.campaign.name) + '</strong> (' + esc(run.campaign.actor) + ').</p>' +
        '</div>' +
        '<div class="cra-row">' +
          '<button class="cru-btn ghost" id="cra-toggle"></button>' +
          '<button class="cru-btn ghost" id="cra-rerun">Re-run vs this campaign</button>' +
          '<button class="cru-btn" id="cra-aar">After-Action</button>' +
        '</div>' +
      '</div>' +
      '<div id="cra-banner"></div>' +
      '<div class="cru-kpis" id="cra-kpis" style="margin:14px 0"></div>' +
      '<div class="cru-card cra-policy" id="cra-policy"></div>' +
      '<div class="cra-cols" style="margin-top:14px">' +
        '<div class="cru-card cra-tracewrap">' +
          '<h3>Agent reasoning trace</h3>' +
          '<p class="cru-sub">Observation to action, per detection. Newest at the top.</p>' +
          '<div class="cra-trace" id="cra-trace"><div class="cra-idle">Awaiting detections from the range…</div></div>' +
        '</div>' +
        '<div class="cru-card"><h3>Containment status</h3><div id="cra-status"></div></div>' +
      '</div>';
    renderToggle(); renderBanner(); renderKpis(); renderStatus(); renderPolicy();
  }

  function wireControls() {
    const tg = container.querySelector('#cra-toggle');
    if (tg) tg.onclick = () => {
      const now = !core.CRU.autopilot;
      core.CRU.autopilot = now; run.autopilot = now;
      renderToggle();
      ctx.toast(now ? 'Autopilot armed — auto-containment on' : 'Manual mode — approvals required', now ? 'good' : 'info');
      if (now) flushPending(); // auto-apply anything awaiting approval
    };
    const rr = container.querySelector('#cra-rerun');
    if (rr) rr.onclick = () => {
      stopTicker();
      core.resetRun(run);
      processed.clear(); pending.clear(); monitored.clear();
      const tr = container.querySelector('#cra-trace');
      if (tr) tr.innerHTML = '<div class="cra-idle">Run re-armed. Autopilot is driving the attacker again…</div>';
      renderBanner(); renderKpis(); renderStatus(); renderPolicy();
      startTicker(); // Autopilot drives the fresh run itself
      ctx.toast('Run reset — re-engaging ' + run.campaign.name, 'info');
    };
    const aar = container.querySelector('#cra-aar');
    if (aar) aar.onclick = () => ctx.go('afteraction');
  }

  function renderToggle() {
    const tg = container.querySelector('#cra-toggle');
    if (!tg) return;
    const on = !!core.CRU.autopilot;
    tg.textContent = on ? 'Mode: Autonomous' : 'Mode: Manual approval';
    tg.classList.toggle('cra-on', on);
  }

  // ======================= THE AGENT LOOP ==================================
  // For each alert: observe -> assess path -> decide actions -> act -> outcome.
  function ingest(alert, isBacklog) {
    if (!alive() || !alert || processed.has(alert.id)) return;
    processed.add(alert.id);

    const a = assess(alert);
    const decision = decide(alert);
    const entry = buildEntry(alert, a, decision);
    const trace = container.querySelector('#cra-trace');
    if (!trace) return;
    const idle = trace.querySelector('.cra-idle');
    if (idle) idle.remove();
    trace.insertBefore(entry.el, trace.firstChild);
    renderKpis();

    if (!decision.actionIds.length) {
      setDecideLine(entry, 'No containment maps to this tactic. Escalating to analyst review.', 'amber');
      renderPolicy();
      return;
    }

    const pol = policy();
    if (core.CRU.autopilot) {
      if (a.priority >= pol.threshold) {
        // Autonomous: priority clears the policy bar -> deliberate, apply, log.
        setDecideLine(entry,
          'DECIDE: ' + decision.names.join(' + ') + ' — priority P' + a.priority +
          ' at/above threshold T' + pol.threshold + ' (' + pol.name + '), executing…', 'amber');
        later(() => applyDecision(alert, decision, entry), isBacklog ? 200 : 400);
      } else {
        // Below the bar: hold and monitor. Raising aggressiveness reconsiders it.
        monitored.set(alert.id, { entry: entry, decision: decision, priority: a.priority });
        setDecideLine(entry,
          'MONITOR: priority P' + a.priority + ' below auto-contain threshold T' + pol.threshold +
          ' (' + pol.name + '). Holding — raise aggressiveness to contain.', 'amber');
      }
    } else {
      // Manual: hold for a human. Approve applies; Dismiss stands down.
      pending.set(alert.id, { actionIds: decision.actionIds, applied: false, entry: entry });
      renderApproval(alert, decision, entry);
    }
    renderPolicy();
  }

  // Re-evaluate held (monitored) alerts after the policy is loosened so a raise
  // in aggressiveness measurably changes the live outcome.
  function reconsider() {
    if (!core.CRU.autopilot) return;
    const pol = policy();
    Array.from(monitored.keys()).forEach((id) => {
      const m = monitored.get(id);
      if (!m || m.priority < pol.threshold) return;
      const alert = run.alerts.find((x) => x.id === id);
      monitored.delete(id);
      if (!alert) return;
      const decision = decide(alert);
      if (m.entry && m.entry.actionsEl) m.entry.actionsEl.innerHTML = '';
      applyDecision(alert, decision, m.entry);
    });
  }

  function applyDecision(alert, decision, entry) {
    if (!alive()) return;
    const notes = [];
    decision.actionIds.forEach((id) => {
      const r = core.applyAction(run, id, alert.id);
      if (r && r.ok) notes.push((core.ACTION[id] || {}).name || id);
    });
    const p = pending.get(alert.id); if (p) p.applied = true;
    monitored.delete(alert.id);
    setDecideLine(entry,
      'APPLIED: ' + (notes.join(' + ') || decision.names.join(' + ')) +
      ' — mttd ' + fmtMin(alert.t) + (run.contained ? ' — CONTAINED' : ''), 'green');
    renderStatus(); renderKpis(); renderBanner(); renderPolicy();
  }

  function renderApproval(alert, decision, entry) {
    const host = entry.actionsEl;
    host.innerHTML = '';
    const ok = document.createElement('button');
    ok.className = 'cru-btn'; ok.style.padding = '5px 12px'; ok.style.fontSize = '.76rem';
    ok.textContent = 'Approve: ' + decision.names.join(' + ');
    ok.onclick = () => {
      host.innerHTML = '';
      applyDecision(alert, decision, entry);
    };
    const no = document.createElement('button');
    no.className = 'cru-btn ghost'; no.style.padding = '5px 12px'; no.style.fontSize = '.76rem';
    no.textContent = 'Dismiss';
    no.onclick = () => {
      const al = run.alerts.find((x) => x.id === alert.id); if (al) al.status = 'dismissed';
      pending.delete(alert.id);
      host.innerHTML = '';
      setDecideLine(entry, 'DISMISSED by analyst — no action taken.', 'red');
    };
    host.appendChild(ok); host.appendChild(no);
    setDecideLine(entry, 'RECOMMEND: ' + decision.names.join(' + ') + ' — awaiting analyst approval.', 'amber');
  }

  function flushPending() {
    pending.forEach((p, id) => {
      if (p.applied) return;
      const alert = run.alerts.find((x) => x.id === id);
      if (!alert) return;
      if (p.entry && p.entry.actionsEl) p.entry.actionsEl.innerHTML = '';
      applyDecision(alert, { actionIds: p.actionIds, names: p.actionIds.map((x) => (core.ACTION[x] || {}).name || x) }, p.entry);
    });
  }

  // ---- reasoning primitives -----------------------------------------------
  function assess(alert) {
    const asset = core.ASSET[alert.assetId] || { id: alert.assetId, name: alert.assetName, zone: 'corp', crit: 3 };
    const zone = core.ESTATE.zones.find((z) => z.id === asset.zone) || { name: asset.zone, trust: 2 };
    const isCrown = CJ.includes(asset.id);
    // Deepest crown jewel the campaign actually drives at = the objective.
    const crownTargets = run.campaign.steps.map((s) => s.targetAssetId).filter((id) => CJ.includes(id));
    const objAsset = core.ASSET[crownTargets.length ? crownTargets[crownTargets.length - 1] : CJ[0]] || { name: 'crown jewels' };
    const tacName = tacticName(alert.tactic);
    let path;
    if (isCrown) path = tacName + ' directly on crown jewel ' + asset.name;
    else path = tacName + ' at ' + asset.name + ' (' + zone.name + ', trust ' + zone.trust + ') — pivot toward crown jewel ' + objAsset.name;
    // Priority: severity + crown proximity + how far down the kill chain.
    let pr = sevMap[alert.severity] || 3;
    pr += isCrown ? 3 : 1;
    const order = core.TACTIC_ORDER[alert.tactic] || 0;
    pr += Math.round((order / Math.max(1, core.TACTICS.length - 1)) * 3);
    pr = Math.min(10, pr);
    return { asset: asset, zone: zone, isCrown: isCrown, objAsset: objAsset, tacName: tacName, priority: pr, path: path };
  }

  function decide(alert) {
    let ids = (alert.suggested && alert.suggested.length) ? alert.suggested.slice() : core.suggestActions(alert.tactic);
    ids = ids.filter((id) => core.ACTION[id]).slice(0, policy().maxActions);
    return { actionIds: ids, names: ids.map((id) => (core.ACTION[id] || {}).name || id) };
  }

  // ---- trace entry DOM -----------------------------------------------------
  function buildEntry(alert, a, decision) {
    const el = document.createElement('div');
    el.className = 'cra-entry';
    const sevCls = 'cru-sev-' + (alert.severity || 'medium');
    el.innerHTML =
      '<div class="cra-entry-head">' +
        '<span class="cra-pri" title="Priority">P' + a.priority + '</span>' +
        '<span class="cra-tech">' + esc(alert.techniqueId) + ' ' + esc(alert.techniqueName) + '</span>' +
        '<span class="cra-sev ' + sevCls + '">' + esc(alert.severity || 'medium') + '</span>' +
        '<span class="cra-time">' + fmtMin(alert.t) + '</span>' +
      '</div>' +
      '<div class="cra-line"><span class="cra-k">OBSERVE</span> ' + esc(alert.detection) + ' via ' + esc(alert.sensor) + ' on ' + esc(alert.assetName) + ' (crit ' + ((a.asset.crit) || '?') + ')</div>' +
      '<div class="cra-line"><span class="cra-k">ASSESS</span> ' + esc(a.path) + (a.isCrown ? ' <span class="cra-flag">CROWN JEWEL</span>' : '') + '</div>' +
      '<div class="cra-line cra-decide"><span class="cra-k">DECIDE</span> <span class="cra-decide-txt">Reasoning…</span></div>' +
      '<div class="cra-actions"></div>';
    return { el: el, decideEl: el.querySelector('.cra-decide-txt'), actionsEl: el.querySelector('.cra-actions') };
  }

  function setDecideLine(entry, text, tone) {
    if (!entry || !entry.decideEl) return;
    entry.decideEl.textContent = text;
    entry.decideEl.className = 'cra-decide-txt' + (tone ? ' cra-' + tone : '');
  }

  // ======================= STATUS / KPIS / BANNER ==========================
  function renderStatus() {
    const host = container.querySelector('#cra-status');
    if (!host) return;
    const blocked = Object.keys(run.blockedTactics || {});
    const blockChips = blocked.length
      ? blocked.map((t) => '<span class="cra-chip cra-block">' + esc(tacticName(t)) + '</span>').join('')
      : '<span class="cru-sub">None yet</span>';
    const acts = (run.actions || []).slice().reverse();
    const actList = acts.length
      ? acts.map((x) => '<li><span class="cra-time">' + fmtMin(x.t) + '</span> ' + esc(x.name) + '</li>').join('')
      : '<li class="cru-sub">No containment applied yet</li>';
    host.innerHTML =
      '<div class="cra-status-block"><div class="cra-k">Blocked tactics</div><div class="cra-chips">' + blockChips + '</div></div>' +
      '<div class="cra-status-block"><div class="cra-k">Containment actions (' + acts.length + ')</div><ul class="cra-actlist">' + actList + '</ul></div>';
  }

  // ---- defense-policy panel: tunable aggressiveness + live tradeoff meters --
  function renderPolicy() {
    const host = container.querySelector('#cra-policy');
    if (!host) return;
    const pol = policy();
    const aggs = core.AGGRESSIONS || [];
    const seg = aggs.map((a) => (
      '<button type="button" class="cra-agg' + (a.id === pol.id ? ' on' : '') +
        '" data-agg="' + esc(a.id) + '" title="' + esc(a.desc) + '">' + esc(a.name) + '</button>'
    )).join('');

    const contained = (run.actions || []).length;
    const held = monitored.size;
    const reasoned = processed.size;

    // The core tradeoff: how much of the campaign's kill chain is now blocked
    // (containment) versus how much of it we managed to alert on (detection).
    const campTactics = Array.from(new Set((run.campaign.steps || [])
      .map((s) => (core.TECH[s.techniqueId] || {}).tactic).filter(Boolean)));
    const blockedCov = campTactics.filter((t) => (run.blockedTactics || {})[t]).length;
    const containCovPct = campTactics.length ? Math.round(blockedCov / campTactics.length * 100) : 0;
    const detCovPct = run.events.length ? Math.round(run.alerts.length / run.events.length * 100) : 0;

    host.innerHTML =
      '<div class="cra-policy-head">' +
        '<div><h3 style="margin:0">Defense Policy</h3>' +
          '<p class="cru-sub" style="margin:2px 0 0">' + esc(pol.desc) + '</p></div>' +
        '<div class="cra-agg-seg" role="group" aria-label="Containment aggressiveness">' + seg + '</div>' +
      '</div>' +
      '<div class="cra-policy-grid">' +
        metric('Auto-contain at', 'P' + pol.threshold + '+') +
        metric('Actions / alert', String(pol.maxActions)) +
        metric('Alerts reasoned', String(reasoned)) +
        metric('Contained', String(contained)) +
        metric('Held / monitor', String(held)) +
      '</div>' +
      '<div class="cra-meter-row">' +
        meter('Containment coverage', containCovPct, blockedCov + ' / ' + campTactics.length + ' tactics blocked', '#16a34a') +
        meter('Detection coverage', detCovPct, run.alerts.length + ' / ' + run.events.length + ' steps alerted', '#d97706') +
      '</div>';

    host.querySelectorAll('.cra-agg').forEach((b) => {
      b.onclick = () => {
        const id = b.dataset.agg;
        if (!core.AGGRESSION || !core.AGGRESSION[id] || id === core.CRU.aggressiveness) return;
        core.CRU.aggressiveness = id;
        const p = policy();
        renderPolicy();
        ctx.toast('Policy: ' + p.name + ' — auto-contain at P' + p.threshold + '+', 'info');
        reconsider();
      };
    });
  }

  function metric(l, n) {
    return '<div class="cra-metric"><div class="cra-metric-n">' + esc(n) +
      '</div><div class="cra-metric-l">' + esc(l) + '</div></div>';
  }
  function meter(label, pct, sub, color) {
    const p = Math.max(0, Math.min(100, Number(pct) || 0));
    return '<div class="cra-meter">' +
      '<div class="cra-meter-top"><span>' + esc(label) + '</span><span>' + esc(pct) + '%</span></div>' +
      '<div class="cra-meter-bar"><div class="cra-meter-fill" style="width:' + p + '%;background:' + color + '"></div></div>' +
      '<div class="cra-meter-sub">' + esc(sub) + '</div>' +
    '</div>';
  }

  function renderKpis() {
    const host = container.querySelector('#cra-kpis');
    if (!host) return;
    const mttd = run.alerts.length ? fmtMin(run.alerts[0].t) : '—';
    const modeTxt = core.CRU.autopilot ? 'Autonomous' : 'Manual';
    host.innerHTML =
      kpi(processed.size, 'Alerts reasoned') +
      kpi((run.actions || []).length, 'Actions taken') +
      kpi(Object.keys(run.blockedTactics || {}).length, 'Tactics blocked') +
      kpi(mttd, 'Time to detect') +
      kpi(modeTxt, 'Agent mode');
  }

  function renderBanner() {
    const host = container.querySelector('#cra-banner');
    if (!host) return;
    let cls = 'cra-neutral', title, sub;
    if (run.contained) {
      cls = 'cra-good'; title = 'Threat Contained';
      sub = 'Autopilot cut the kill chain at ' + fmtMin(run.containedAt != null ? run.containedAt : run.clockMin) + '. Remaining adversary actions are blocked.';
    } else if (run.done) {
      const sc = safeScore();
      if (sc && sc.crownHit && sc.crownHit.length) {
        cls = 'cra-bad'; title = 'Attacker Reached Objective';
        sub = 'The adversary reached ' + sc.crownHit.length + ' crown-jewel asset(s) before containment. Review the After-Action for gaps.';
      } else {
        cls = 'cra-warn'; title = 'Engagement Complete';
        sub = 'Campaign ended without full containment, but no crown jewel was compromised.';
      }
    } else {
      title = 'Engagement Active';
      sub = 'Agent is monitoring the range and will ' + (core.CRU.autopilot ? 'auto-contain' : 'recommend containment for') + ' each detection.';
    }
    host.innerHTML =
      '<div class="cra-banner ' + cls + '">' +
        '<div class="cra-banner-title">' + esc(title) + '</div>' +
        '<div class="cra-banner-sub">' + esc(sub) + '</div>' +
        (run.done ? '<button class="cru-btn ghost" id="cra-banner-aar" style="margin-top:8px">Open After-Action</button>' : '') +
      '</div>';
    const b = host.querySelector('#cra-banner-aar');
    if (b) b.onclick = () => ctx.go('afteraction');
  }

  // ======================= helpers =========================================
  function safeScore() { try { return core.scoreRun(run); } catch (_) { return null; } }
  function tacticName(id) { const t = core.TACTICS.find((x) => x.id === id); return t ? t.name : id; }
  function fmtMin(m) { return (m == null ? '—' : 't+' + m + 'm'); }
  function kpi(n, l) { return '<div class="cru-kpi"><div class="cru-kpi-n">' + esc(n) + '</div><div class="cru-kpi-l">' + esc(l) + '</div></div>'; }
  function assetsLabel() {
    const n = (core.ESTATE.assets || []).length;
    return n + ' assets / ' + CJ.length + ' crown jewels';
  }

  // ======================= scoped styles ===================================
  function styleBlock() {
    return '<style>' +
      '.cra-topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;flex-wrap:wrap;margin-bottom:6px}' +
      '.cra-row{display:flex;gap:8px;flex-wrap:wrap}' +
      '.cra-empty{text-align:center;padding:40px 20px}.cra-empty .cra-row{justify-content:center;margin-top:14px}' +
      '.cra-cols{display:grid;grid-template-columns:1.4fr 1fr;gap:14px;align-items:start}' +
      '@media (max-width:820px){.cra-cols{grid-template-columns:1fr}}' +
      '.cra-tracewrap{display:flex;flex-direction:column;min-height:0}' +
      '.cra-trace{margin-top:8px;max-height:520px;overflow:auto;display:flex;flex-direction:column;gap:8px}' +
      '.cra-idle{color:var(--mut);font-size:.8rem;padding:18px 4px}' +
      '.cra-entry{border:1px solid var(--line);border-radius:4px;padding:9px 11px;background:color-mix(in srgb,var(--acc) 4%,var(--card))}' +
      '.cra-entry-head{display:flex;align-items:center;gap:8px;margin-bottom:5px;flex-wrap:wrap}' +
      '.cra-pri{font-weight:800;font-size:.7rem;background:var(--acc);color:#fff;border-radius:4px;padding:1px 6px;letter-spacing:.04em}' +
      '.cra-tech{font-weight:700;font-size:.82rem}' +
      '.cra-sev{font-size:.64rem;text-transform:uppercase;letter-spacing:.08em;font-weight:700}' +
      '.cra-time{margin-left:auto;font-size:.68rem;color:var(--mut);font-variant-numeric:tabular-nums}' +
      '.cra-line{font-size:.76rem;line-height:1.5;color:var(--txt)}' +
      '.cra-k{display:inline-block;min-width:62px;font-size:.62rem;font-weight:700;letter-spacing:.1em;color:var(--mut)}' +
      '.cra-flag{font-size:.6rem;font-weight:700;letter-spacing:.08em;color:#dc2626;border:1px solid #dc2626;border-radius:4px;padding:0 5px;margin-left:4px}' +
      '.cra-decide-txt{color:var(--mut)}' +
      '.cra-green{color:#16a34a;font-weight:600}.cra-amber{color:#d97706;font-weight:600}.cra-red{color:#dc2626;font-weight:600}' +
      '.cra-actions{display:flex;gap:8px;margin-top:7px;flex-wrap:wrap}' +
      '.cra-status-block{margin-bottom:14px}.cra-status-block:last-child{margin-bottom:0}' +
      '.cra-chips{display:flex;gap:6px;flex-wrap:wrap;margin-top:6px}' +
      '.cra-chip{font-size:.68rem;padding:2px 8px;border-radius:4px;border:1px solid var(--line)}' +
      '.cra-block{border-color:#16a34a;color:#16a34a;background:color-mix(in srgb,#16a34a 10%,transparent)}' +
      '.cra-actlist{list-style:none;margin:6px 0 0;padding:0;display:flex;flex-direction:column;gap:4px;font-size:.76rem}' +
      '.cra-actlist .cra-time{margin:0 8px 0 0}' +
      '.cra-banner{border:1px solid var(--line);border-radius:8px;padding:12px 14px}' +
      '.cra-banner-title{font-weight:800;font-size:.95rem}.cra-banner-sub{font-size:.78rem;color:var(--mut);margin-top:2px}' +
      '.cra-good{border-color:#16a34a;background:color-mix(in srgb,#16a34a 9%,var(--card))}.cra-good .cra-banner-title{color:#16a34a}' +
      '.cra-bad{border-color:#dc2626;background:color-mix(in srgb,#dc2626 9%,var(--card))}.cra-bad .cra-banner-title{color:#dc2626}' +
      '.cra-warn{border-color:#d97706;background:color-mix(in srgb,#d97706 9%,var(--card))}.cra-warn .cra-banner-title{color:#d97706}' +
      '.cra-neutral{background:var(--card)}' +
      '#cra-toggle.cra-on{border-color:#16a34a;color:#16a34a}' +
      '.cra-policy-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap}' +
      '.cra-agg-seg{display:inline-flex;border:1px solid var(--line);border-radius:4px;overflow:hidden;flex:none}' +
      '.cra-agg{font-family:inherit;color:var(--txt);background:var(--card);border:0;border-left:1px solid var(--line);padding:7px 14px;cursor:pointer;font-size:.74rem;font-weight:600;letter-spacing:.02em}' +
      '.cra-agg:first-child{border-left:0}' +
      '.cra-agg:hover{background:color-mix(in srgb,var(--acc) 8%,var(--card))}' +
      '.cra-agg.on{background:var(--acc);color:#fff}' +
      '.cra-policy-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(120px,1fr));gap:10px;margin-top:14px}' +
      '.cra-metric{border:1px solid var(--line);border-radius:4px;padding:8px 10px;background:color-mix(in srgb,var(--acc) 4%,var(--card))}' +
      '.cra-metric-n{font-size:1.1rem;font-weight:800;font-variant-numeric:tabular-nums}' +
      '.cra-metric-l{font-size:.62rem;letter-spacing:.05em;text-transform:uppercase;color:var(--mut);margin-top:2px}' +
      '.cra-meter-row{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:14px}' +
      '@media (max-width:640px){.cra-meter-row{grid-template-columns:1fr}}' +
      '.cra-meter-top{display:flex;justify-content:space-between;font-size:.72rem;font-weight:600;margin-bottom:5px}' +
      '.cra-meter-bar{height:8px;border-radius:4px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden}' +
      '.cra-meter-fill{height:100%;border-radius:4px;transition:width .3s}' +
      '.cra-meter-sub{font-size:.64rem;color:var(--mut);margin-top:4px}' +
      '</style>';
  }
}
