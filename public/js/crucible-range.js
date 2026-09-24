// Darknode Project - CRUCIBLE :: Wargame Range
// Pillar: build and launch adversary campaigns against the simulated estate.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Export contract: renderRange(container, ctx)
//   ctx = { go(tabId), toast(msg, kind), core }
// All data, engine and helpers come from ctx.core (crucible-core.js).
// Everything here is SYNTHETIC — simulation / training only.

export function renderRange(container, ctx) {
  const core = ctx.core;
  const esc = core.esc;

  // ------------------------------------------------------------------ state
  let selectedCampaign = (core.CRU.run && core.CRU.run.campaignId) ||
    (core.CAMPAIGNS[0] && core.CAMPAIGNS[0].id) || null;
  let selectedPosture = (core.POSTURES[0] && core.POSTURES[0].id) || null;
  let selectedDifficulty = core.CRU.difficulty ||
    ((core.DIFFICULTIES || []).find((d) => d.id === 'standard') || (core.DIFFICULTIES || [])[0] || {}).id || null;
  let timer = null;         // active step interval
  let running = false;

  function stopTimer() {
    if (timer) { clearInterval(timer); timer = null; }
  }

  // -------------------------------------------------------------- helpers
  // Distinct MITRE tactics a campaign exercises, in kill-chain order.
  function campaignTactics(camp) {
    const seen = {};
    const ids = [];
    (camp.steps || []).forEach((s) => {
      const t = core.TECH[s.techniqueId];
      const tac = t && t.tactic;
      if (tac && !seen[tac]) { seen[tac] = 1; ids.push(tac); }
    });
    ids.sort((a, b) => (core.TACTIC_ORDER[a] ?? 99) - (core.TACTIC_ORDER[b] ?? 99));
    return ids.map((id) => {
      const def = core.TACTICS.find((x) => x.id === id);
      return { id, name: def ? def.name : id };
    });
  }

  function sevClassForCrit(crit) {
    const c = Number(crit) || 0;
    if (c >= 5) return 'critical';
    if (c >= 4) return 'high';
    if (c >= 3) return 'medium';
    return 'low';
  }

  // Sophistication as text pips/bars (NO emoji).
  function pips(level, max) {
    const n = Math.max(0, Math.min(max || 5, Number(level) || 0));
    let out = '<span class="crr-pips" aria-label="' + esc(n + ' of ' + (max || 5)) + '">';
    for (let i = 0; i < (max || 5); i++) {
      out += '<span class="crr-pip' + (i < n ? ' on' : '') + '"></span>';
    }
    out += '</span>';
    return out;
  }

  // ----------------------------------------------------------- estate panel
  function estateHTML() {
    const zones = core.ESTATE.zones || [];
    const assets = core.ESTATE.assets || [];
    const crown = core.ESTATE.crownJewels || [];
    let cols = '';
    zones.forEach((z) => {
      const inZone = assets.filter((a) => a.zone === z.id);
      const rows = inZone.map((a) => {
        const isCrown = crown.includes(a.id);
        return (
          '<div class="crr-asset">' +
            '<div class="crr-asset-top">' +
              '<span class="crr-asset-name">' + esc(a.name) +
                (isCrown ? '<span class="crr-crown" title="Crown jewel">CJ</span>' : '') +
              '</span>' +
              '<span class="crr-sev crr-sev-' + sevClassForCrit(a.crit) + '">crit ' + esc(a.crit) + '</span>' +
            '</div>' +
            '<div class="crr-asset-meta">' +
              '<span>' + esc(a.ip) + '</span>' +
              '<span>' + esc(a.os) + '</span>' +
              '<span>' + esc(a.type) + '</span>' +
            '</div>' +
            '<div class="crr-services">' +
              (a.services || []).map((s) => '<span class="crr-tag">' + esc(s) + '</span>').join('') +
            '</div>' +
          '</div>'
        );
      }).join('') || '<div class="cru-sub">No assets.</div>';
      cols += (
        '<div class="crr-zone">' +
          '<div class="crr-zone-head">' +
            '<span class="crr-zone-name">' + esc(z.name) + '</span>' +
            '<span class="crr-zone-trust">trust ' + esc(z.trust) + '</span>' +
          '</div>' +
          rows +
        '</div>'
      );
    });
    return (
      '<div class="cru-card">' +
        '<h3>Simulated Estate</h3>' +
        '<p class="cru-sub">Read-only view of the protected environment. ' +
          esc(assets.length) + ' assets across ' + esc(zones.length) + ' zones. ' +
          'Crown jewels marked CJ.</p>' +
        '<div class="crr-zones">' + cols + '</div>' +
      '</div>'
    );
  }

  // ------------------------------------------------------ campaign library
  function campaignCardsHTML() {
    return (core.CAMPAIGNS || []).map((c) => {
      const tactics = campaignTactics(c);
      const on = c.id === selectedCampaign;
      return (
        '<button type="button" class="crr-camp' + (on ? ' on' : '') + '" data-camp="' + esc(c.id) + '">' +
          '<div class="crr-camp-top">' +
            '<span class="crr-camp-name">' + esc(c.name) + '</span>' +
            '<span class="crr-camp-check">' + (on ? 'SELECTED' : 'SELECT') + '</span>' +
          '</div>' +
          '<div class="crr-camp-actor">' + esc(c.actor) + '</div>' +
          '<div class="crr-camp-soph">' +
            '<span class="crr-soph-l">Sophistication</span>' + pips(c.sophistication, 5) +
          '</div>' +
          '<div class="crr-camp-obj">' + esc(c.objective) + '</div>' +
          '<div class="crr-camp-foot">' +
            '<span class="crr-tag">' + esc((c.steps || []).length) + ' steps</span>' +
            '<span class="crr-tag">' + esc(tactics.length) + ' tactics</span>' +
          '</div>' +
          '<div class="crr-camp-tactics">' +
            tactics.map((t) => '<span class="crr-tac">' + esc(t.name) + '</span>').join('') +
          '</div>' +
        '</button>'
      );
    }).join('');
  }

  // ---------------------------------------------------- kill-chain plan
  // A step-by-step ATT&CK view of the SELECTED campaign, grouped by tactic in
  // kill-chain order. Each step shows its target, dwell, noise and whether the
  // defender has any sensor mapped to that technique (a pre-launch coverage
  // preview). If a run for this campaign exists, each step is overlaid with its
  // live outcome (blocked / detected / reached).
  function planHTML() {
    const camp = core.CAMPAIGN[selectedCampaign];
    if (!camp) return '';
    const steps = camp.steps || [];
    const run = core.CRU.run;
    const overlay = (run && run.campaignId === selectedCampaign) ? run : null;

    // coverage preview: how many distinct techniques have a mapped detection.
    const techIds = steps.map((s) => s.techniqueId);
    const uniqTech = Array.from(new Set(techIds));
    const covered = uniqTech.filter((id) => (core.DET_BY_TECH[id] || []).length).length;
    const crownSteps = steps.filter((s) => (core.ESTATE.crownJewels || []).includes(s.targetAssetId)).length;

    let lastTac = null;
    let rows = '';
    steps.forEach((s, i) => {
      const tech = core.TECH[s.techniqueId] || { id: s.techniqueId, name: s.techniqueId, tactic: 'execution' };
      const asset = core.ASSET[s.targetAssetId] || { id: s.targetAssetId, name: s.targetAssetId };
      const dets = core.DET_BY_TECH[s.techniqueId] || [];
      const isCrown = (core.ESTATE.crownJewels || []).includes(s.targetAssetId);
      if (tech.tactic !== lastTac) {
        lastTac = tech.tactic;
        const tacDef = core.TACTICS.find((t) => t.id === tech.tactic);
        const order = (core.TACTIC_ORDER[tech.tactic] ?? 0) + 1;
        rows +=
          '<div class="crr-plan-phase">' +
            '<span class="crr-plan-phase-n">' + esc(String(order).padStart(2, '0')) + '</span>' +
            '<span class="crr-plan-phase-t">' + esc(tacDef ? tacDef.name : tech.tactic) + '</span>' +
          '</div>';
      }
      // live overlay status from the matching event (events are in step order).
      let statusCls = 'planned', statusTxt = 'planned';
      if (overlay) {
        const ev = overlay.events[i];
        if (ev) {
          const al = overlay.alerts.find((a) => a.techniqueId === ev.techniqueId && a.assetId === ev.assetId && a.t === ev.t);
          if (ev.blocked) { statusCls = 'blocked'; statusTxt = 'blocked'; }
          else if (al) { statusCls = 'detected'; statusTxt = 'detected'; }
          else { statusCls = 'reached'; statusTxt = 'reached'; }
        }
      }
      const cov = dets.length
        ? '<span class="crr-plan-cov ok">' + esc(dets.length) + ' sensor' + (dets.length === 1 ? '' : 's') + ': ' +
            esc(dets.map((d) => d.sensor).join(', ')) + '</span>'
        : '<span class="crr-plan-cov gap">no sensor mapped &middot; blind spot</span>';
      rows +=
        '<div class="crr-plan-step ' + statusCls + '">' +
          '<span class="crr-plan-step-i">' + esc(i + 1) + '</span>' +
          '<span class="crr-plan-step-body">' +
            '<span class="crr-plan-step-l1">' +
              '<span class="crr-plan-tech">' + esc(tech.id) + ' &middot; ' + esc(tech.name) + '</span>' +
              '<span class="crr-plan-status crr-plan-' + statusCls + '">' + esc(statusTxt) + '</span>' +
            '</span>' +
            '<span class="crr-plan-step-l2">' +
              '<span class="crr-plan-tgt">target: ' + esc(asset.name) +
                (isCrown ? ' <span class="crr-crown">CJ</span>' : '') + '</span>' +
              '<span class="crr-plan-meta">dwell ' + esc(s.dwellMin) + 'm &middot; noise ' + esc(Math.round((s.noise || 0) * 100)) + '%</span>' +
            '</span>' +
            '<span class="crr-plan-step-l3">' + cov + '</span>' +
          '</span>' +
        '</div>';
    });

    return (
      '<div class="cru-card" id="crr-plan">' +
        '<div class="crr-exec-head">' +
          '<h3 style="margin:0">Kill-Chain Plan &mdash; ' + esc(camp.name) + '</h3>' +
          '<span class="crr-plan-badge">' + esc(covered) + '/' + esc(uniqTech.length) + ' techniques instrumented</span>' +
        '</div>' +
        '<p class="cru-sub">Projected ATT&amp;CK progression for the selected campaign across ' +
          esc(steps.length) + ' steps' + (crownSteps ? ', ' + esc(crownSteps) + ' targeting crown jewels' : '') +
          '. Blind spots are techniques with no mapped sensor.</p>' +
        '<div class="crr-plan">' + rows + '</div>' +
      '</div>'
    );
  }

  // ------------------------------------------------------- launch controls
  function launchHTML() {
    const postures = (core.POSTURES || []).map((p) => (
      '<button type="button" class="crr-posture' + (p.id === selectedPosture ? ' on' : '') +
        '" data-posture="' + esc(p.id) + '">' +
        '<span class="crr-posture-name">' + esc(p.name) + '</span>' +
        '<span class="crr-posture-mult">x' + esc(p.mult) + ' detect</span>' +
      '</button>'
    )).join('');
    const diffs = (core.DIFFICULTIES || []).map((d) => (
      '<button type="button" class="crr-diff' + (d.id === selectedDifficulty ? ' on' : '') +
        '" data-diff="' + esc(d.id) + '" title="' + esc(d.desc) + '">' +
        '<span class="crr-diff-name">' + esc(d.name) + '</span>' +
        '<span class="crr-diff-mult">detect x' + esc(d.detectMult) + ' &middot; tempo x' + esc(d.dwellMult) + '</span>' +
      '</button>'
    )).join('');
    const selDiff = core.DIFFICULTY ? core.DIFFICULTY[selectedDifficulty] : null;
    return (
      '<div class="cru-card">' +
        '<h3>Launch Controls</h3>' +
        '<p class="cru-sub">Set adversary tradecraft, defensive posture and defender mode, then launch the selected campaign.</p>' +
        '<div class="crr-ctl crr-ctl-full">' +
          '<div class="crr-ctl-l">Adversary Tradecraft (Difficulty)</div>' +
          '<div class="crr-diffs">' + diffs + '</div>' +
          '<div class="cru-sub crr-diff-note" style="margin:8px 0 0">' +
            (selDiff ? esc(selDiff.desc) : '') + '</div>' +
        '</div>' +
        '<div class="crr-ctl-row">' +
          '<div class="crr-ctl">' +
            '<div class="crr-ctl-l">Defensive Posture</div>' +
            '<div class="crr-postures">' + postures + '</div>' +
          '</div>' +
          '<div class="crr-ctl">' +
            '<div class="crr-ctl-l">Defender Mode</div>' +
            '<button type="button" id="crr-auto" class="crr-toggle' + (core.CRU.autopilot ? ' on' : '') + '"' +
              ' aria-pressed="' + (core.CRU.autopilot ? 'true' : 'false') + '">' +
              '<span class="crr-toggle-knob"></span>' +
              '<span class="crr-toggle-txt">' + (core.CRU.autopilot ? 'AUTOPILOT ON' : 'MANUAL') + '</span>' +
            '</button>' +
            '<div class="cru-sub" style="margin:8px 0 0">Autopilot lets the blue team respond autonomously.</div>' +
          '</div>' +
        '</div>' +
        '<div class="crr-launch-bar">' +
          '<button type="button" id="crr-launch" class="cru-btn crr-launch">Launch Wargame</button>' +
          '<span id="crr-launch-hint" class="cru-sub" style="margin:0"></span>' +
        '</div>' +
      '</div>'
    );
  }

  // -------------------------------------------------------- execution panel
  function executionShellHTML() {
    return (
      '<div class="cru-card" id="crr-exec">' +
        '<div class="crr-exec-head">' +
          '<h3 style="margin:0">Kill-Chain Execution</h3>' +
          '<span id="crr-exec-status" class="crr-run-badge">IDLE</span>' +
        '</div>' +
        '<p class="cru-sub" id="crr-exec-sub">Launch a wargame to stream the adversary kill chain here.</p>' +
        '<div class="cru-kpis" id="crr-exec-kpis" style="display:none">' +
          '<div class="cru-kpi"><div class="cru-kpi-n" id="crr-k-step">0</div><div class="cru-kpi-l">Steps run</div></div>' +
          '<div class="cru-kpi"><div class="cru-kpi-n" id="crr-k-alert">0</div><div class="cru-kpi-l">Alerts raised</div></div>' +
          '<div class="cru-kpi"><div class="cru-kpi-n" id="crr-k-block">0</div><div class="cru-kpi-l">Steps blocked</div></div>' +
          '<div class="cru-kpi"><div class="cru-kpi-n" id="crr-k-clock">0m</div><div class="cru-kpi-l">Sim clock</div></div>' +
        '</div>' +
        '<div class="crr-timeline" id="crr-timeline"></div>' +
        '<div class="crr-summary" id="crr-summary" style="display:none"></div>' +
      '</div>'
    );
  }

  // ------------------------------------------------------------- full paint
  function paint() {
    if (!container.isConnected) return;
    container.innerHTML =
      STYLE +
      '<div class="cru-grid crr-wrap">' +
        estateHTML() +
        '<div class="cru-card">' +
          '<h3>Campaign Library</h3>' +
          '<p class="cru-sub">Select an adversary campaign to stage against the estate.</p>' +
          '<div class="crr-camps">' + campaignCardsHTML() + '</div>' +
        '</div>' +
        planHTML() +
        launchHTML() +
        executionShellHTML() +
      '</div>';
    wire();
  }

  // Re-render just the plan card in place (campaign changed, or run advanced).
  function refreshPlan() {
    if (!container.isConnected) return;
    const el = container.querySelector('#crr-plan');
    if (!el) return;
    const tmp = document.createElement('div');
    tmp.innerHTML = planHTML();
    const fresh = tmp.firstElementChild;
    if (fresh) el.replaceWith(fresh);
  }

  function wire() {
    // campaign selection
    container.querySelectorAll('.crr-camp').forEach((b) => {
      b.onclick = () => {
        if (running) return;
        selectedCampaign = b.dataset.camp;
        container.querySelectorAll('.crr-camp').forEach((x) => {
          const on = x === b;
          x.classList.toggle('on', on);
          const chk = x.querySelector('.crr-camp-check');
          if (chk) chk.textContent = on ? 'SELECTED' : 'SELECT';
        });
        refreshPlan();
      };
    });
    // posture selection
    container.querySelectorAll('.crr-posture').forEach((b) => {
      b.onclick = () => {
        if (running) return;
        selectedPosture = b.dataset.posture;
        container.querySelectorAll('.crr-posture').forEach((x) => x.classList.toggle('on', x === b));
      };
    });
    // difficulty selection -- persisted on CRU so it changes the engine on launch
    container.querySelectorAll('.crr-diff').forEach((b) => {
      b.onclick = () => {
        if (running) return;
        selectedDifficulty = b.dataset.diff;
        core.CRU.difficulty = selectedDifficulty;
        container.querySelectorAll('.crr-diff').forEach((x) => x.classList.toggle('on', x === b));
        const note = container.querySelector('.crr-diff-note');
        const d = core.DIFFICULTY ? core.DIFFICULTY[selectedDifficulty] : null;
        if (note && d) note.textContent = d.desc;
      };
    });
    // autopilot toggle
    const auto = container.querySelector('#crr-auto');
    if (auto) auto.onclick = () => {
      if (running) return;
      core.CRU.autopilot = !core.CRU.autopilot;
      auto.classList.toggle('on', core.CRU.autopilot);
      auto.setAttribute('aria-pressed', core.CRU.autopilot ? 'true' : 'false');
      const txt = auto.querySelector('.crr-toggle-txt');
      if (txt) txt.textContent = core.CRU.autopilot ? 'AUTOPILOT ON' : 'MANUAL';
    };
    // launch
    const launch = container.querySelector('#crr-launch');
    if (launch) launch.onclick = () => launchRun();
  }

  // -------------------------------------------------------------- launch
  function launchRun() {
    if (running) return;
    if (!selectedCampaign) { ctx.toast('Select a campaign first', 'bad'); return; }

    const run = core.newRun(selectedCampaign, {
      postureId: selectedPosture,
      autopilot: core.CRU.autopilot,
      difficultyId: selectedDifficulty,
    });
    core.CRU.run = run;

    const camp = run.campaign;
    running = true;

    // lock controls
    const launch = container.querySelector('#crr-launch');
    if (launch) { launch.disabled = true; launch.textContent = 'Wargame Running…'; }
    container.querySelectorAll('.crr-camp,.crr-posture,.crr-diff').forEach((x) => x.classList.add('crr-lock'));

    const status = container.querySelector('#crr-exec-status');
    if (status) { status.textContent = 'RUNNING'; status.className = 'crr-run-badge live'; }
    const sub = container.querySelector('#crr-exec-sub');
    if (sub) sub.textContent = camp.name + ' — ' + camp.actor + ' vs the estate' +
      (core.CRU.autopilot ? ' (autopilot engaged)' : ' (manual defense)');
    const kpis = container.querySelector('#crr-exec-kpis');
    if (kpis) kpis.style.display = '';
    const timeline = container.querySelector('#crr-timeline');
    if (timeline) timeline.innerHTML = '';
    const summary = container.querySelector('#crr-summary');
    if (summary) { summary.style.display = 'none'; summary.innerHTML = ''; }

    ctx.toast('Launching ' + camp.name, 'info');

    let steps = 0, alerts = 0, blocked = 0;

    // animated stepping loop
    timer = setInterval(() => {
      if (!container.isConnected) { stopTimer(); running = false; return; }
      const res = core.stepRun(run);

      (res.events || []).forEach((ev) => {
        steps += 1;
        if (ev.blocked) blocked += 1;
        // find the alert raised for this event (matched by asset+technique)
        const al = (res.alerts || []).find((a) => a.assetId === ev.assetId && a.techniqueId === ev.techniqueId);
        if (al) alerts += 1;
        appendTimelineRow(ev, al);
      });

      // KPI refresh
      setText('#crr-k-step', String(steps));
      setText('#crr-k-alert', String(alerts));
      setText('#crr-k-block', String(blocked));
      setText('#crr-k-clock', run.clockMin + 'm');
      refreshPlan();

      if (res.done) {
        stopTimer();
        finishRun(run);
      }
    }, 350);
  }

  function setText(sel, val) {
    if (!container.isConnected) return;
    const el = container.querySelector(sel);
    if (el) el.textContent = val;
  }

  function appendTimelineRow(ev, al) {
    if (!container.isConnected) return;
    const timeline = container.querySelector('#crr-timeline');
    if (!timeline) return;
    const tacDef = core.TACTICS.find((t) => t.id === ev.tactic);
    const tacName = tacDef ? tacDef.name : ev.tactic;
    const row = document.createElement('div');
    row.className = 'crr-tl-row' + (ev.blocked ? ' blocked' : (al ? ' alerted' : ''));
    const sevCls = al ? ('crr-sev-' + (al.severity || 'medium')) : '';
    row.innerHTML =
      '<span class="crr-tl-clock">' + esc(ev.t) + 'm</span>' +
      '<span class="crr-tl-dot"></span>' +
      '<span class="crr-tl-body">' +
        '<span class="crr-tl-line1">' +
          '<span class="crr-tl-tech">' + esc(ev.techniqueId) + ' · ' + esc(ev.techniqueName) + '</span>' +
          '<span class="crr-tl-tac">' + esc(tacName) + '</span>' +
        '</span>' +
        '<span class="crr-tl-line2">' +
          '<span class="crr-tl-target">target: ' + esc(ev.assetName) + '</span>' +
          (ev.blocked
            ? '<span class="crr-tl-flag crr-sev-low">BLOCKED</span>'
            : (al
                ? '<span class="crr-tl-flag ' + esc(sevCls) + '">ALERT · ' + esc(al.detection) + ' (' + esc(al.severity) + ')</span>'
                : '<span class="crr-tl-flag crr-tl-miss">no detection</span>')) +
        '</span>' +
      '</span>';
    timeline.appendChild(row);
    timeline.scrollTop = timeline.scrollHeight;
  }

  function finishRun(run) {
    running = false;
    if (!container.isConnected) return;
    refreshPlan();
    const score = core.scoreRun(run);
    const status = container.querySelector('#crr-exec-status');
    if (status) {
      status.textContent = run.contained ? 'CONTAINED' : 'COMPLETE';
      status.className = 'crr-run-badge ' + (run.contained ? 'done-good' : 'done');
    }

    const outcome = run.contained
      ? ('Campaign CONTAINED at ' + run.containedAt + 'm.')
      : (score.crownHit.length
          ? ('Adversary reached ' + score.crownHit.length + ' crown jewel(s).')
          : 'Campaign ran to completion.');
    const crownNames = score.crownHit.map((id) => (core.ASSET[id] ? core.ASSET[id].name : id));

    const summary = container.querySelector('#crr-summary');
    if (summary) {
      summary.style.display = '';
      summary.innerHTML =
        '<div class="crr-sum-line">' +
          '<span class="crr-sum-grade crr-grade-' + esc(score.grade) + '">' + esc(score.grade) + '</span>' +
          '<span class="crr-sum-txt">' + esc(outcome) +
            ' Detection ' + esc(score.detectionRate) + '%' +
            (score.mttdMin != null ? (' · MTTD ' + esc(score.mttdMin) + 'm') : ' · no detection') +
            ' · Score ' + esc(score.score) + '/100.' +
            (crownNames.length ? ' Crown jewels hit: ' + esc(crownNames.join(', ')) + '.' : '') +
          '</span>' +
        '</div>' +
        '<div class="crr-sum-btns">' +
          '<button type="button" class="cru-btn" data-go="fusion">Open Fusion Command</button>' +
          '<button type="button" class="cru-btn ghost" data-go="autopilot">Run Autopilot</button>' +
          '<button type="button" class="cru-btn ghost" data-go="afteraction">After-Action Report</button>' +
          '<button type="button" class="cru-btn ghost" id="crr-reset">New Wargame</button>' +
        '</div>';
      summary.querySelectorAll('[data-go]').forEach((b) => {
        b.onclick = () => ctx.go(b.dataset.go);
      });
      const reset = summary.querySelector('#crr-reset');
      if (reset) reset.onclick = () => { core.CRU.run = null; paint(); };
    }

    ctx.toast(run.contained ? 'Adversary contained' : 'Wargame complete — grade ' + score.grade,
      run.contained ? 'good' : (score.crownHit.length ? 'bad' : 'info'));
  }

  // ---------------------------------------------------- disconnect watchdog
  // Clear the interval if the container is torn out mid-run.
  const watchdog = setInterval(() => {
    if (!container.isConnected) {
      stopTimer();
      clearInterval(watchdog);
    }
  }, 800);

  // ---------------------------------------------------------------- styles
  const STYLE = '<style>' +
    '.crr-wrap{grid-template-columns:1fr}' +
    '.crr-zones{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}' +
    '.crr-zone{border:1px solid var(--line);border-radius:6px;padding:10px;background:color-mix(in srgb,var(--acc) 4%,var(--card))}' +
    '.crr-zone-head{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px;padding-bottom:6px;border-bottom:1px solid var(--line)}' +
    '.crr-zone-name{font-weight:700;font-size:.8rem}' +
    '.crr-zone-trust{font-size:.64rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}' +
    '.crr-asset{border:1px solid var(--line);border-radius:4px;padding:8px;margin-bottom:8px;background:var(--card)}' +
    '.crr-asset:last-child{margin-bottom:0}' +
    '.crr-asset-top{display:flex;justify-content:space-between;align-items:center;gap:8px}' +
    '.crr-asset-name{font-weight:600;font-size:.8rem;display:inline-flex;align-items:center;gap:6px}' +
    '.crr-crown{font-size:.56rem;font-weight:800;letter-spacing:.05em;padding:1px 4px;border-radius:3px;background:color-mix(in srgb,#d97706 20%,transparent);color:#d97706;border:1px solid color-mix(in srgb,#d97706 45%,transparent)}' +
    '.crr-asset-meta{display:flex;gap:10px;flex-wrap:wrap;font-size:.68rem;color:var(--mut);margin-top:4px}' +
    '.crr-services{display:flex;gap:4px;flex-wrap:wrap;margin-top:6px}' +
    '.crr-tag{font-size:.62rem;padding:2px 6px;border:1px solid var(--line);border-radius:3px;color:var(--mut)}' +
    '.crr-sev{font-size:.62rem;font-weight:700;letter-spacing:.04em}' +
    '.crr-sev-critical{color:#dc2626}.crr-sev-high{color:#ea580c}.crr-sev-medium{color:#d97706}.crr-sev-low{color:#16a34a}' +
    '.crr-camps{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}' +
    '.crr-camp{text-align:left;font-family:inherit;color:var(--txt);background:var(--card);border:1px solid var(--line);border-radius:6px;padding:12px;cursor:pointer;display:flex;flex-direction:column;gap:6px;transition:border-color .15s,box-shadow .15s}' +
    '.crr-camp:hover{border-color:var(--acc)}' +
    '.crr-camp.on{border-color:var(--acc);box-shadow:inset 0 0 0 1px var(--acc);background:color-mix(in srgb,var(--acc) 8%,var(--card))}' +
    '.crr-camp.crr-lock,.crr-posture.crr-lock{opacity:.55;cursor:default}' +
    '.crr-camp-top{display:flex;justify-content:space-between;align-items:center;gap:8px}' +
    '.crr-camp-name{font-weight:800;letter-spacing:.05em;font-size:.9rem}' +
    '.crr-camp-check{font-size:.58rem;font-weight:700;letter-spacing:.08em;color:var(--acc)}' +
    '.crr-camp-actor{font-size:.72rem;color:var(--mut);text-transform:uppercase;letter-spacing:.06em}' +
    '.crr-camp-soph{display:flex;align-items:center;justify-content:space-between;gap:8px}' +
    '.crr-soph-l{font-size:.66rem;color:var(--mut)}' +
    '.crr-pips{display:inline-flex;gap:3px}' +
    '.crr-pip{width:14px;height:6px;border-radius:2px;background:color-mix(in srgb,var(--txt) 16%,transparent)}' +
    '.crr-pip.on{background:var(--acc)}' +
    '.crr-camp-obj{font-size:.74rem;color:var(--txt);opacity:.9}' +
    '.crr-camp-foot{display:flex;gap:6px}' +
    '.crr-camp-tactics{display:flex;flex-wrap:wrap;gap:4px}' +
    '.crr-tac{font-size:.6rem;padding:2px 6px;border-radius:3px;background:color-mix(in srgb,var(--acc) 10%,transparent);border:1px solid color-mix(in srgb,var(--acc) 30%,transparent);color:var(--txt)}' +
    '.crr-ctl-row{display:grid;grid-template-columns:1fr 1fr;gap:16px}' +
    '.crr-ctl-l{font-size:.68rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);margin-bottom:8px}' +
    '.crr-postures{display:flex;flex-wrap:wrap;gap:8px}' +
    '.crr-posture{font-family:inherit;color:var(--txt);background:var(--card);border:1px solid var(--line);border-radius:4px;padding:8px 12px;cursor:pointer;display:flex;flex-direction:column;gap:2px;min-width:120px}' +
    '.crr-posture:hover{border-color:var(--acc)}' +
    '.crr-posture.on{border-color:var(--acc);box-shadow:inset 0 0 0 1px var(--acc);background:color-mix(in srgb,var(--acc) 10%,var(--card))}' +
    '.crr-posture-name{font-weight:700;font-size:.78rem}' +
    '.crr-posture-mult{font-size:.62rem;color:var(--mut)}' +
    '.crr-toggle{display:inline-flex;align-items:center;gap:8px;font-family:inherit;color:var(--txt);background:var(--card);border:1px solid var(--line);border-radius:4px;padding:8px 12px;cursor:pointer}' +
    '.crr-toggle-knob{width:34px;height:18px;border-radius:9px;background:color-mix(in srgb,var(--txt) 18%,transparent);position:relative;transition:background .15s;flex:none}' +
    '.crr-toggle-knob:after{content:"";position:absolute;top:2px;left:2px;width:14px;height:14px;border-radius:50%;background:var(--card);transition:transform .15s}' +
    '.crr-toggle.on .crr-toggle-knob{background:var(--acc)}' +
    '.crr-toggle.on .crr-toggle-knob:after{transform:translateX(16px)}' +
    '.crr-toggle-txt{font-size:.72rem;font-weight:700;letter-spacing:.05em}' +
    '.crr-ctl-full{margin-bottom:16px}' +
    '.crr-diffs{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:8px}' +
    '.crr-diff{font-family:inherit;text-align:left;color:var(--txt);background:var(--card);border:1px solid var(--line);border-radius:4px;padding:8px 12px;cursor:pointer;display:flex;flex-direction:column;gap:3px}' +
    '.crr-diff:hover{border-color:var(--acc)}' +
    '.crr-diff.on{border-color:var(--acc);box-shadow:inset 0 0 0 1px var(--acc);background:color-mix(in srgb,var(--acc) 10%,var(--card))}' +
    '.crr-diff.crr-lock{opacity:.55;cursor:default}' +
    '.crr-diff-name{font-weight:700;font-size:.8rem}' +
    '.crr-diff-mult{font-size:.6rem;color:var(--mut);font-variant-numeric:tabular-nums}' +
    '.crr-plan-badge{font-size:.62rem;font-weight:700;letter-spacing:.06em;padding:3px 8px;border-radius:4px;border:1px solid var(--line);color:var(--mut)}' +
    '.crr-plan{margin-top:12px;display:flex;flex-direction:column;gap:5px;max-height:420px;overflow-y:auto}' +
    '.crr-plan-phase{display:flex;align-items:center;gap:8px;margin:8px 0 3px;padding-bottom:3px;border-bottom:1px solid var(--line)}' +
    '.crr-plan-phase:first-child{margin-top:0}' +
    '.crr-plan-phase-n{font-size:.6rem;font-weight:800;color:var(--acc);font-variant-numeric:tabular-nums}' +
    '.crr-plan-phase-t{font-size:.68rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}' +
    '.crr-plan-step{display:flex;gap:10px;align-items:flex-start;padding:7px 10px;border:1px solid var(--line);border-radius:4px;background:var(--card)}' +
    '.crr-plan-step.blocked{border-left:3px solid #16a34a}' +
    '.crr-plan-step.detected{border-left:3px solid #d97706}' +
    '.crr-plan-step.reached{border-left:3px solid #dc2626}' +
    '.crr-plan-step-i{font-size:.66rem;color:var(--mut);min-width:18px;font-variant-numeric:tabular-nums;padding-top:2px;font-weight:700}' +
    '.crr-plan-step-body{flex:1;min-width:0;display:flex;flex-direction:column;gap:3px}' +
    '.crr-plan-step-l1{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}' +
    '.crr-plan-tech{font-weight:600;font-size:.78rem}' +
    '.crr-plan-status{font-size:.6rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;padding:1px 6px;border-radius:3px;border:1px solid var(--line);color:var(--mut)}' +
    '.crr-plan-blocked{color:#16a34a;border-color:color-mix(in srgb,#16a34a 45%,transparent)}' +
    '.crr-plan-detected{color:#d97706;border-color:color-mix(in srgb,#d97706 45%,transparent)}' +
    '.crr-plan-reached{color:#dc2626;border-color:color-mix(in srgb,#dc2626 45%,transparent)}' +
    '.crr-plan-step-l2{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;font-size:.7rem;color:var(--mut)}' +
    '.crr-plan-tgt{display:inline-flex;align-items:center;gap:6px}' +
    '.crr-plan-meta{font-variant-numeric:tabular-nums}' +
    '.crr-plan-step-l3{font-size:.66rem}' +
    '.crr-plan-cov{display:inline-block}' +
    '.crr-plan-cov.ok{color:#16a34a}' +
    '.crr-plan-cov.gap{color:#dc2626;font-weight:600}' +
    '.crr-launch-bar{display:flex;align-items:center;gap:14px;margin-top:16px;flex-wrap:wrap}' +
    '.crr-launch{font-size:.9rem;padding:11px 22px;letter-spacing:.04em}' +
    '.crr-exec-head{display:flex;align-items:center;justify-content:space-between;gap:10px}' +
    '.crr-run-badge{font-size:.62rem;font-weight:800;letter-spacing:.1em;padding:3px 8px;border-radius:4px;border:1px solid var(--line);color:var(--mut)}' +
    '.crr-run-badge.live{color:#dc2626;border-color:color-mix(in srgb,#dc2626 50%,transparent);background:color-mix(in srgb,#dc2626 12%,transparent)}' +
    '.crr-run-badge.done{color:#d97706;border-color:color-mix(in srgb,#d97706 50%,transparent)}' +
    '.crr-run-badge.done-good{color:#16a34a;border-color:color-mix(in srgb,#16a34a 50%,transparent);background:color-mix(in srgb,#16a34a 12%,transparent)}' +
    '.crr-timeline{margin-top:14px;max-height:360px;overflow-y:auto;display:flex;flex-direction:column;gap:6px}' +
    '.crr-tl-row{display:flex;gap:10px;align-items:flex-start;padding:8px 10px;border:1px solid var(--line);border-radius:4px;background:var(--card);animation:crr-in .25s ease}' +
    '.crr-tl-row.alerted{border-left:3px solid #dc2626}' +
    '.crr-tl-row.blocked{border-left:3px solid #16a34a;opacity:.85}' +
    '@keyframes crr-in{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:none}}' +
    '.crr-tl-clock{font-size:.66rem;color:var(--mut);min-width:34px;font-variant-numeric:tabular-nums;padding-top:2px}' +
    '.crr-tl-dot{width:8px;height:8px;border-radius:50%;background:var(--acc);margin-top:4px;flex:none}' +
    '.crr-tl-row.alerted .crr-tl-dot{background:#dc2626}.crr-tl-row.blocked .crr-tl-dot{background:#16a34a}' +
    '.crr-tl-body{flex:1;min-width:0}' +
    '.crr-tl-line1{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap}' +
    '.crr-tl-tech{font-weight:600;font-size:.78rem}' +
    '.crr-tl-tac{font-size:.64rem;color:var(--mut);text-transform:uppercase;letter-spacing:.05em}' +
    '.crr-tl-line2{display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;margin-top:3px}' +
    '.crr-tl-target{font-size:.7rem;color:var(--mut)}' +
    '.crr-tl-flag{font-size:.64rem;font-weight:700;letter-spacing:.03em}' +
    '.crr-tl-miss{color:var(--mut);font-weight:600}' +
    '.crr-summary{margin-top:16px;padding-top:14px;border-top:1px solid var(--line)}' +
    '.crr-sum-line{display:flex;gap:12px;align-items:center}' +
    '.crr-sum-grade{font-size:1.5rem;font-weight:800;width:44px;height:44px;display:inline-flex;align-items:center;justify-content:center;border:2px solid var(--line);border-radius:6px;flex:none}' +
    '.crr-grade-A{color:#16a34a;border-color:#16a34a}.crr-grade-B{color:#65a30d;border-color:#65a30d}.crr-grade-C{color:#d97706;border-color:#d97706}.crr-grade-D{color:#ea580c;border-color:#ea580c}.crr-grade-F{color:#dc2626;border-color:#dc2626}' +
    '.crr-sum-txt{font-size:.82rem;line-height:1.4}' +
    '.crr-sum-btns{display:flex;flex-wrap:wrap;gap:8px;margin-top:14px}' +
    '@media (max-width:640px){.crr-ctl-row{grid-template-columns:1fr}}' +
    '</style>';

  // ------------------------------------------------------------- first paint
  paint();
}
