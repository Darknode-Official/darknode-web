// Darknode Project - CRUCIBLE :: After-Action
// Pillar: score the exercise, render MITRE coverage, expose gaps, timeline,
// Security Graph export and a printable report. All data synthetic.
// Copyright (c) 2026 Darknode-Official. All rights reserved.
//
// Exports: renderAfterAction(container, ctx)
//   ctx = { go(tabId), toast(msg, kind), core }  (core = crucible-core exports)
// This pillar imports NOTHING from crucible-core directly; it uses ctx.core.

export function renderAfterAction(container, ctx) {
  const { core } = ctx;
  const esc = core.esc;

  // -- collect reviewable runs: active first, then history (dedupe by id) --
  const pool = [];
  const seen = new Set();
  const push = (r) => { if (r && r.id && !seen.has(r.id)) { seen.add(r.id); pool.push(r); } };
  push(core.CRU.run);
  (core.CRU.history || []).forEach(push);

  if (!pool.length) {
    container.innerHTML =
      styleBlock() +
      '<div class="cru-card caa-empty">' +
        '<h3>No exercise to score yet</h3>' +
        '<p class="cru-sub">Run an adversary campaign on the Wargame Range, then return here for the after-action review, MITRE ATT&amp;CK coverage and report.</p>' +
        '<button class="cru-btn" id="caa-goRange">Go to Wargame Range</button>' +
      '</div>';
    const b = container.querySelector('#caa-goRange');
    if (b) b.onclick = () => ctx.go('range');
    return;
  }

  let selectedId = pool[0].id;

  function currentRun() {
    return pool.find((r) => r.id === selectedId) || pool[0];
  }

  // ----------------------------- helpers -----------------------------------
  // red (low coverage) -> green (high coverage) via color-mix on the value
  function covColor(pct) {
    const p = Math.max(0, Math.min(100, pct));
    return 'color-mix(in srgb, #16a34a ' + p + '%, #dc2626)';
  }
  function gradeColor(grade) {
    return grade === 'A' ? '#16a34a' : grade === 'B' ? '#65a30d'
      : grade === 'C' ? '#d97706' : grade === 'D' ? '#ea580c' : '#dc2626';
  }
  function fmtMin(m) {
    if (m == null) return '—';
    const h = Math.floor(m / 60), mm = m % 60;
    return h ? (h + 'h ' + mm + 'm') : (mm + 'm');
  }
  function assetName(id) {
    const a = core.ASSET[id];
    return a ? a.name : id;
  }
  function tacticName(id) {
    const t = (core.TACTICS || []).find((x) => x.id === id);
    return t ? t.name : id;
  }

  // ---- derived response metrics (computed over the run, not scoreRun) -------
  function responseMetrics(run, s) {
    const crown = core.ESTATE.crownJewels || [];
    const exposureMin = run.contained ? (run.containedAt != null ? run.containedAt : run.clockMin) : run.clockMin;
    // MTTR: mean gap between an alert firing and a containment action citing it.
    let rtSum = 0, rtN = 0;
    (run.actions || []).forEach((act) => {
      if (!act.alertId) return;
      const al = (run.alerts || []).find((x) => x.id === act.alertId);
      if (al && act.t >= al.t) { rtSum += (act.t - al.t); rtN += 1; }
    });
    const mttrMin = rtN ? Math.round(rtSum / rtN) : null;
    // Dwell to first crown-jewel contact (undetected reach counts as dwell).
    let crownDwellMin = null;
    (run.events || []).forEach((e) => {
      if (crownDwellMin != null) return;
      if (!e.blocked && crown.indexOf(e.assetId) !== -1) crownDwellMin = e.t;
    });
    const blockedSteps = (run.events || []).filter((e) => e.blocked).length;
    return { exposureMin, mttrMin, crownDwellMin, blockedSteps };
  }

  // ---- per-technique scoring rows (in execution order) ---------------------
  function perTechniqueRows(run) {
    return (run.events || []).map((e, i) => {
      const al = (run.alerts || []).find((a) => a.techniqueId === e.techniqueId && a.assetId === e.assetId && a.t === e.t);
      const status = e.blocked ? 'blocked' : (al ? 'detected' : 'missed');
      return {
        i: i + 1, techId: e.techniqueId, techName: e.techniqueName || e.techniqueId,
        tactic: e.tactic, assetName: e.assetName || assetName(e.assetId),
        isCrown: (core.ESTATE.crownJewels || []).indexOf(e.assetId) !== -1,
        t: e.t, status: status, sensor: al ? al.sensor : '', detection: al ? al.detection : '',
        severity: al ? al.severity : '',
      };
    });
  }

  // ---- rule-based lessons & recommendations from the scored outcome --------
  function recommendations(run, s, camp, posture) {
    const recs = [];
    // 1. Detection gaps grouped by tactic -> instrument / tune.
    const gapTactics = {};
    s.missed.forEach((m) => {
      const tac = (core.TECH[m.techniqueId] || {}).tactic;
      if (!tac) return;
      (gapTactics[tac] || (gapTactics[tac] = [])).push(m.techniqueId);
    });
    Object.keys(gapTactics).forEach((tac) => {
      const existing = core.detectionsByTactic(tac);
      const n = gapTactics[tac].length;
      if (existing.length) {
        recs.push({ sev: 'high', title: 'Tune ' + tacticName(tac) + ' detection',
          detail: n + ' technique(s) executed undetected despite ' + existing.length + ' mapped sensor(s) (' +
            existing.slice(0, 2).map((d) => d.sensor).join(', ') + '). Raise fidelity or broaden coverage on this tactic.' });
      } else {
        recs.push({ sev: 'critical', title: 'Build ' + tacticName(tac) + ' detection',
          detail: 'No sensor is mapped to ' + tacticName(tac) + ' — a true blind spot the adversary used ' + n + ' time(s). Add telemetry here first.' });
      }
    });
    // 2. Crown jewels reached -> segmentation.
    if (s.crownHit.length) {
      const names = s.crownHit.map((id) => (core.ASSET[id] || { name: id }).name);
      recs.push({ sev: 'critical', title: 'Segment reached crown jewels',
        detail: 'Adversary reached ' + names.join(', ') + '. Tighten zone segmentation and enforce host isolation earlier on the path to these assets.' });
    }
    // 3. Time-to-detect quality.
    if (s.mttdMin == null) {
      recs.push({ sev: 'critical', title: 'No detection fired',
        detail: 'The campaign ran end to end without a single alert. Instrument initial-access and execution tactics as the top priority.' });
    } else if (s.mttdMin > 90) {
      recs.push({ sev: 'high', title: 'Cut mean time to detect',
        detail: 'First detection landed at ' + fmtMin(s.mttdMin) + '. Move earlier-kill-chain sensors up and consider an elevated posture at onboarding.' });
    }
    // 4. Containment outcome / autopilot policy.
    const pol = (core.AGGRESSION && core.AGGRESSION[core.CRU.aggressiveness]) || null;
    if (!s.contained) {
      recs.push({ sev: 'high', title: 'Contain earlier in the kill chain',
        detail: 'The threat was never fully contained' + (pol ? ' under the ' + pol.name + ' policy' : '') +
          '. A more aggressive autopilot policy or faster analyst approvals would cut the kill chain sooner.' });
    } else {
      recs.push({ sev: 'low', title: 'Containment succeeded',
        detail: 'The kill chain was cut at ' + fmtMin(run.containedAt) + '. Preserve this playbook and rehearse it against faster tradecraft.' });
    }
    // 5. Posture vs difficulty context.
    if (posture && posture.id === 'baseline' && s.detectionRate < 60) {
      recs.push({ sev: 'medium', title: 'Raise standing posture',
        detail: 'Detection rate was ' + s.detectionRate + '% at Baseline posture. An elevated posture measurably lifts every detection roll.' });
    }
    if (run.difficulty && (run.difficulty.id === 'elite' || run.difficulty.id === 'apex')) {
      recs.push({ sev: 'medium', title: 'Validated against ' + run.difficulty.name + ' tradecraft',
        detail: 'This exercise used low-noise, high-tempo tradecraft (detect x' + run.difficulty.detectMult +
          '). Gaps here are the ones most likely to matter against a real advanced adversary.' });
    }
    return recs;
  }

  // ------------------------------ view -------------------------------------
  function render() {
    if (!container.isConnected) return;
    const run = currentRun();
    const s = core.scoreRun(run);
    const camp = run.campaign || core.CAMPAIGN[run.campaignId] || {};
    const posture = core.POSTURE[run.postureId] || { name: run.postureId || 'Baseline' };

    container.innerHTML = styleBlock() + [
      headerHTML(run, camp, posture),
      scoreCardHTML(s),
      metricsHTML(run, s),
      heatmapHTML(s),
      perTechniqueHTML(run),
      gapsHTML(s),
      recommendationsHTML(run, s, camp, posture),
      timelineHTML(run),
      actionsHTML(),
      '<div id="caa-report-slot"></div>',
    ].join('');

    wire(run, s, camp, posture);
  }

  function headerHTML(run, camp, posture) {
    const opts = pool.map((r) => {
      const c = r.campaign || core.CAMPAIGN[r.campaignId] || {};
      const active = core.CRU.run && r.id === core.CRU.run.id ? ' (current)' : '';
      const label = (c.name || r.campaignId || r.id) + active;
      return '<option value="' + esc(r.id) + '"' + (r.id === selectedId ? ' selected' : '') + '>' + esc(label) + '</option>';
    }).join('');
    const selector = pool.length > 1
      ? '<label class="caa-selwrap">Review<select id="caa-runsel" class="caa-sel">' + opts + '</select></label>'
      : '';
    const outcome = run.contained
      ? '<span class="cru-sev-low">Contained at ' + esc(fmtMin(run.containedAt)) + '</span>'
      : (run.reached && run.reached.length ? '<span class="cru-sev-high">Objective progressed</span>' : '<span class="cru-sev-medium">Incomplete</span>');
    return (
      '<div class="cru-card caa-head">' +
        '<div class="caa-head-l">' +
          '<h3>' + esc(camp.name || 'Exercise') + ' — After-Action</h3>' +
          '<p class="cru-sub">' + esc(camp.actor || 'Unknown actor') + ' &middot; Posture: ' + esc(posture.name) + ' &middot; Outcome: ' + outcome + '</p>' +
          (camp.objective ? '<p class="caa-obj">Objective: ' + esc(camp.objective) + '</p>' : '') +
        '</div>' +
        (selector ? '<div class="caa-head-r">' + selector + '</div>' : '') +
      '</div>'
    );
  }

  function scoreCardHTML(s) {
    const kpis = [
      ['Detection Rate', s.detectionRate + '%', ''],
      ['MTTD', s.mttdMin == null ? '—' : (s.mttdMin + ' min'), ''],
      ['Contained', s.contained ? ('Yes @ ' + fmtMin(s.containedAt)) : 'No', s.contained ? 'cru-sev-low' : 'cru-sev-high'],
      ['Crown Jewels Reached', String(s.crownHit.length), s.crownHit.length ? 'cru-sev-critical' : 'cru-sev-low'],
      ['Techniques Detected', s.detectedSteps + ' / ' + s.totalTechniques, ''],
    ].map(([l, n, cls]) =>
      '<div class="cru-kpi"><div class="cru-kpi-n ' + cls + '">' + esc(n) + '</div><div class="cru-kpi-l">' + esc(l) + '</div></div>'
    ).join('');
    return (
      '<div class="caa-scorewrap">' +
        '<div class="cru-card caa-grade" style="border-color:' + gradeColor(s.grade) + '">' +
          '<div class="caa-grade-g" style="color:' + gradeColor(s.grade) + '">' + esc(s.grade) + '</div>' +
          '<div class="caa-grade-meta">' +
            '<div class="caa-grade-n">' + s.score + '<span>/100</span></div>' +
            '<div class="cru-kpi-l">Exercise Score</div>' +
          '</div>' +
        '</div>' +
        '<div class="cru-kpis caa-kpis">' + kpis + '</div>' +
      '</div>'
    );
  }

  function metricsHTML(run, s) {
    const m = responseMetrics(run, s);
    const tiles = [
      ['Exposure Window', fmtMin(m.exposureMin), ''],
      ['Mean Time to Detect', s.mttdMin == null ? '—' : fmtMin(s.mttdMin), s.mttdMin == null ? 'cru-sev-high' : ''],
      ['Mean Time to Respond', m.mttrMin == null ? '—' : fmtMin(m.mttrMin), ''],
      ['Dwell to Crown Jewel', m.crownDwellMin == null ? 'not reached' : fmtMin(m.crownDwellMin), m.crownDwellMin == null ? 'cru-sev-low' : 'cru-sev-critical'],
      ['Steps Blocked', String(m.blockedSteps), m.blockedSteps ? 'cru-sev-low' : ''],
    ].map(([l, n, cls]) =>
      '<div class="cru-kpi"><div class="cru-kpi-n ' + cls + '">' + esc(n) + '</div><div class="cru-kpi-l">' + esc(l) + '</div></div>'
    ).join('');
    return (
      '<div class="cru-card">' +
        '<h3>Response Metrics</h3>' +
        '<p class="cru-sub">Dwell and timing derived from the engagement. Exposure is the window the adversary operated; MTTR is the mean gap between a detection and the containment action that cited it.</p>' +
        '<div class="cru-kpis">' + tiles + '</div>' +
      '</div>'
    );
  }

  function perTechniqueHTML(run) {
    const rows = perTechniqueRows(run);
    if (!rows.length) return '';
    const body = rows.map((r) => {
      const tag = r.status === 'blocked' ? '<span class="caa-tl-tag caa-tl-block">blocked</span>'
        : r.status === 'detected' ? '<span class="caa-tl-tag caa-tl-det">detected</span>'
        : '<span class="caa-tl-tag caa-tl-miss">undetected</span>';
      const sensor = r.status === 'detected' ? esc(r.sensor) + (r.detection ? ' (' + esc(r.detection) + ')' : '') : '<span class="caa-none-txt">—</span>';
      return (
        '<div class="caa-pt-row caa-pt-' + r.status + '">' +
          '<span class="caa-pt-i">' + esc(r.i) + '</span>' +
          '<span class="caa-pt-tech"><span class="caa-pt-id">' + esc(r.techId) + '</span> ' + esc(r.techName) +
            '<span class="caa-pt-tac">' + esc(tacticName(r.tactic)) + '</span></span>' +
          '<span class="caa-pt-tgt">' + esc(r.assetName) + (r.isCrown ? ' <span class="caa-pt-cj">CJ</span>' : '') + '</span>' +
          '<span class="caa-pt-t">' + esc(fmtMin(r.t)) + '</span>' +
          '<span class="caa-pt-sensor">' + sensor + '</span>' +
          '<span class="caa-pt-status">' + tag + '</span>' +
        '</div>'
      );
    }).join('');
    return (
      '<div class="cru-card">' +
        '<h3>Per-Technique Scoring</h3>' +
        '<p class="cru-sub">Every technique the adversary executed, in order, with the detection outcome and the sensor that caught it.</p>' +
        '<div class="caa-pt-head">' +
          '<span class="caa-pt-i">#</span><span class="caa-pt-tech">Technique</span>' +
          '<span class="caa-pt-tgt">Target</span><span class="caa-pt-t">Time</span>' +
          '<span class="caa-pt-sensor">Sensor</span><span class="caa-pt-status">Outcome</span>' +
        '</div>' +
        '<div class="caa-pt">' + body + '</div>' +
      '</div>'
    );
  }

  function recommendationsHTML(run, s, camp, posture) {
    const recs = recommendations(run, s, camp, posture);
    if (!recs.length) return '';
    const items = recs.map((r) =>
      '<li class="caa-rec caa-rec-' + esc(r.sev) + '">' +
        '<span class="caa-rec-sev cru-sev-' + esc(r.sev) + '">' + esc(r.sev) + '</span>' +
        '<span class="caa-rec-body"><span class="caa-rec-t">' + esc(r.title) + '</span>' +
          '<span class="caa-rec-d">' + esc(r.detail) + '</span></span>' +
      '</li>'
    ).join('');
    return (
      '<div class="cru-card">' +
        '<h3>Lessons &amp; Recommendations</h3>' +
        '<p class="cru-sub">Prioritised actions generated from this exercise\'s detection gaps, dwell metrics and containment outcome.</p>' +
        '<ul class="caa-recs">' + items + '</ul>' +
      '</div>'
    );
  }

  function heatmapHTML(s) {
    const cells = core.TACTICS.map((t) => {
      const pct = s.mitre[t.id];
      const exercised = pct != null;
      const val = exercised ? pct : 0;
      const bg = exercised ? covColor(val) : 'transparent';
      const barW = exercised ? val : 0;
      return (
        '<div class="caa-cell' + (exercised ? '' : ' caa-cell-na') + '">' +
          '<div class="caa-cell-top">' +
            '<span class="caa-cell-name">' + esc(t.name) + '</span>' +
            '<span class="caa-cell-val">' + (exercised ? (val + '%') : 'n/a') + '</span>' +
          '</div>' +
          '<div class="caa-cell-bar"><div class="caa-cell-fill" style="width:' + barW + '%;background:' + bg + '"></div></div>' +
        '</div>'
      );
    }).join('');
    return (
      '<div class="cru-card">' +
        '<h3>MITRE ATT&amp;CK Coverage</h3>' +
        '<p class="cru-sub">Detection coverage per tactic the adversary exercised. Red indicates blind spots; green indicates strong detection.</p>' +
        '<div class="caa-heat">' + cells + '</div>' +
      '</div>'
    );
  }

  function gapsHTML(s) {
    const missed = s.missed.length
      ? s.missed.map((m) =>
          '<li><span class="caa-gap-t">' + esc(m.techniqueName || m.techniqueId) + '</span>' +
          '<span class="caa-gap-a">' + esc(assetName(m.assetId)) + '</span>' +
          '<span class="caa-gap-id">' + esc(m.techniqueId) + '</span></li>'
        ).join('')
      : '<li class="caa-none">Every executed technique produced at least one alert.</li>';
    const crown = s.crownHit.length
      ? s.crownHit.map((id) => {
          const a = core.ASSET[id] || { name: id };
          return '<li><span class="caa-gap-t cru-sev-critical">' + esc(a.name) + '</span>' +
            '<span class="caa-gap-a">' + esc((a.zone && (core.ESTATE.zones.find((z) => z.id === a.zone) || {}).name) || a.zone || '') + '</span>' +
            '<span class="caa-gap-id">' + esc(a.ip || '') + '</span></li>';
        }).join('')
      : '<li class="caa-none">No crown-jewel assets were reached. Well defended.</li>';
    return (
      '<div class="cru-grid caa-gap-grid">' +
        '<div class="cru-card">' +
          '<h3>Detection Gaps</h3>' +
          '<p class="cru-sub">Techniques the attacker executed with no corresponding alert.</p>' +
          '<ul class="caa-gaps">' + missed + '</ul>' +
        '</div>' +
        '<div class="cru-card">' +
          '<h3>Critical Findings</h3>' +
          '<p class="cru-sub">Crown-jewel assets the attacker reached.</p>' +
          '<ul class="caa-gaps">' + crown + '</ul>' +
        '</div>' +
      '</div>'
    );
  }

  // merge attacker events and defender actions into one chronological narrative
  function mergedTimeline(run) {
    const rows = [];
    (run.events || []).forEach((e) => {
      const detected = (run.alerts || []).some((a) => a.techniqueId === e.techniqueId && a.assetId === e.assetId && a.t === e.t);
      rows.push({ t: e.t, side: 'atk', blocked: e.blocked, detected,
        title: (e.techniqueName || e.techniqueId), target: e.assetName || assetName(e.assetId) });
    });
    (run.actions || []).forEach((a) => {
      rows.push({ t: a.t, side: 'def', title: a.name, target: '' });
    });
    rows.sort((x, y) => (x.t - y.t) || (x.side === 'atk' ? -1 : 1));
    return rows;
  }

  function timelineHTML(run) {
    const rows = mergedTimeline(run);
    if (!rows.length) return '';
    const items = rows.map((r) => {
      if (r.side === 'atk') {
        const tag = r.blocked ? '<span class="caa-tl-tag caa-tl-block">blocked</span>'
          : r.detected ? '<span class="caa-tl-tag caa-tl-det">detected</span>'
          : '<span class="caa-tl-tag caa-tl-miss">undetected</span>';
        return (
          '<div class="caa-tl-row caa-tl-atk">' +
            '<span class="caa-tl-t">' + esc(fmtMin(r.t)) + '</span>' +
            '<span class="caa-tl-dot"></span>' +
            '<span class="caa-tl-body"><span class="caa-tl-who">ADVERSARY</span> ' + esc(r.title) +
              (r.target ? ' <span class="caa-tl-target">&rarr; ' + esc(r.target) + '</span>' : '') + ' ' + tag + '</span>' +
          '</div>'
        );
      }
      return (
        '<div class="caa-tl-row caa-tl-def">' +
          '<span class="caa-tl-t">' + esc(fmtMin(r.t)) + '</span>' +
          '<span class="caa-tl-dot"></span>' +
          '<span class="caa-tl-body"><span class="caa-tl-who caa-tl-who-def">DEFENDER</span> ' + esc(r.title) + '</span>' +
        '</div>'
      );
    }).join('');
    return (
      '<div class="cru-card">' +
        '<h3>Engagement Timeline</h3>' +
        '<p class="cru-sub">Attacker steps against defender actions, in the order they occurred.</p>' +
        '<div class="caa-tl">' + items + '</div>' +
      '</div>'
    );
  }

  function actionsHTML() {
    return (
      '<div class="caa-actions">' +
        '<button class="cru-btn" id="caa-export">Export to Security Graph</button>' +
        '<button class="cru-btn ghost" id="caa-report">Generate Report</button>' +
      '</div>'
    );
  }

  // ------------------------- graph export ----------------------------------
  function buildGraphItems(run, s, camp) {
    const items = [];
    items.push({
      type: 'REPORT',
      name: (camp.name || 'Exercise') + ' After-Action',
      data: { grade: s.grade, score: s.score, detectionRate: s.detectionRate, mttdMin: s.mttdMin, contained: s.contained },
      opts: { tags: ['crucible', 'simulated'], severity: s.crownHit.length ? 'high' : 'medium' },
    });
    s.missed.forEach((m) => {
      items.push({
        type: 'FINDING',
        name: 'Undetected: ' + (m.techniqueName || m.techniqueId) + ' on ' + assetName(m.assetId),
        data: { techniqueId: m.techniqueId, technique: m.techniqueName, asset: assetName(m.assetId), kind: 'detection-gap' },
        opts: { tags: ['crucible', 'simulated'], severity: 'medium' },
      });
    });
    s.crownHit.forEach((id) => {
      const a = core.ASSET[id] || { name: id };
      items.push({
        type: 'FINDING',
        name: 'Crown jewel reached: ' + a.name,
        data: { asset: a.name, ip: a.ip, zone: a.zone, kind: 'crown-jewel-reach' },
        opts: { tags: ['crucible', 'simulated'], severity: 'critical' },
      });
    });
    s.reached.forEach((id) => {
      const a = core.ASSET[id];
      if (!a) return;
      items.push({
        type: 'ASSET',
        name: a.name,
        data: { ip: a.ip, zone: a.zone, type: a.type, os: a.os },
        opts: { tags: ['crucible', 'simulated'] },
      });
    });
    return items;
  }

  async function exportToGraph(run, s, camp, btn) {
    if (btn) btn.disabled = true;
    try {
      const gb = await import('/js/graph-bridge.js?v=20260923c');
      if (!container.isConnected) return;
      if (typeof gb.sendToGraph !== 'function') {
        ctx.toast('Security Graph export is unavailable', 'bad');
        return;
      }
      const items = buildGraphItems(run, s, camp);
      const res = gb.sendToGraph('CRUCIBLE', items) || {};
      const created = res.created || 0, updated = res.updated || 0;
      ctx.toast('Security Graph: ' + created + ' added, ' + updated + ' updated', 'good');
    } catch (e) {
      if (container.isConnected) ctx.toast('Graph export failed: ' + (e && e.message ? e.message : e), 'bad');
    } finally {
      if (btn && container.isConnected) btn.disabled = false;
    }
  }

  // ------------------------- printable report ------------------------------
  function buildReportText(run, s, camp, posture) {
    const L = [];
    L.push('CRUCIBLE AFTER-ACTION REPORT (SIMULATED EXERCISE)');
    L.push('='.repeat(52));
    L.push('Campaign : ' + (camp.name || 'Exercise'));
    L.push('Actor    : ' + (camp.actor || 'Unknown'));
    L.push('Objective: ' + (camp.objective || '—'));
    L.push('Posture  : ' + posture.name);
    L.push('');
    L.push('OUTCOME');
    L.push('-'.repeat(52));
    L.push('Grade            : ' + s.grade + '  (' + s.score + '/100)');
    L.push('Detection rate   : ' + s.detectionRate + '%  (' + s.detectedSteps + '/' + s.totalTechniques + ' techniques)');
    L.push('Mean time to detect (MTTD): ' + (s.mttdMin == null ? 'never detected' : s.mttdMin + ' min'));
    L.push('Contained        : ' + (s.contained ? 'yes, at ' + fmtMin(s.containedAt) : 'no'));
    L.push('Crown jewels hit : ' + s.crownHit.length);
    L.push('');
    const rm = responseMetrics(run, s);
    L.push('RESPONSE METRICS');
    L.push('-'.repeat(52));
    L.push('Exposure window        : ' + fmtMin(rm.exposureMin));
    L.push('Mean time to detect    : ' + (s.mttdMin == null ? 'never' : fmtMin(s.mttdMin)));
    L.push('Mean time to respond   : ' + (rm.mttrMin == null ? 'n/a' : fmtMin(rm.mttrMin)));
    L.push('Dwell to crown jewel   : ' + (rm.crownDwellMin == null ? 'not reached' : fmtMin(rm.crownDwellMin)));
    L.push('Steps blocked          : ' + rm.blockedSteps);
    L.push('');
    L.push('PER-TECHNIQUE SCORING');
    L.push('-'.repeat(52));
    perTechniqueRows(run).forEach((r) => {
      L.push('  ' + String(r.i).padStart(2, ' ') + '. ' + r.techId + ' ' + (r.techName || '').padEnd(28, ' ').slice(0, 28) +
        ' [' + r.status + ']' + (r.sensor ? ' via ' + r.sensor : ''));
    });
    L.push('');
    L.push('MITRE ATT&CK COVERAGE');
    L.push('-'.repeat(52));
    core.TACTICS.forEach((t) => {
      const pct = s.mitre[t.id];
      const val = pct == null ? 'n/a' : (pct + '%');
      L.push('  ' + t.name.padEnd(26, ' ') + val);
    });
    L.push('');
    L.push('DETECTION GAPS (undetected techniques)');
    L.push('-'.repeat(52));
    if (s.missed.length) s.missed.forEach((m) => L.push('  - ' + (m.techniqueName || m.techniqueId) + ' [' + m.techniqueId + '] on ' + assetName(m.assetId)));
    else L.push('  none');
    L.push('');
    L.push('CRITICAL FINDINGS (crown jewels reached)');
    L.push('-'.repeat(52));
    if (s.crownHit.length) s.crownHit.forEach((id) => { const a = core.ASSET[id] || { name: id }; L.push('  - ' + a.name + ' (' + (a.ip || '') + ', zone ' + (a.zone || '') + ')'); });
    else L.push('  none');
    L.push('');
    L.push('LESSONS & RECOMMENDATIONS');
    L.push('-'.repeat(52));
    const recs = recommendations(run, s, camp, posture);
    if (recs.length) recs.forEach((r) => {
      L.push('  [' + r.sev.toUpperCase() + '] ' + r.title);
      L.push('        ' + r.detail);
    });
    else L.push('  none');
    L.push('');
    L.push('TIMELINE');
    L.push('-'.repeat(52));
    mergedTimeline(run).forEach((r) => {
      const who = r.side === 'atk' ? 'ADVERSARY' : 'DEFENDER ';
      const state = r.side === 'atk' ? (r.blocked ? ' [blocked]' : r.detected ? ' [detected]' : ' [undetected]') : '';
      L.push('  ' + fmtMin(r.t).padStart(6, ' ') + '  ' + who + '  ' + r.title + (r.target ? ' -> ' + r.target : '') + state);
    });
    L.push('');
    L.push('Generated by CRUCIBLE. All data synthetic.');
    return L.join('\n');
  }

  function showReport(run, s, camp, posture) {
    const slot = container.querySelector('#caa-report-slot');
    if (!slot) return;
    const text = buildReportText(run, s, camp, posture);
    slot.innerHTML =
      '<div class="cru-card caa-report">' +
        '<div class="caa-report-head">' +
          '<h3>After-Action Report</h3>' +
          '<div class="caa-report-btns">' +
            '<button class="cru-btn ghost" id="caa-copy">Copy</button>' +
            '<button class="cru-btn ghost" id="caa-close">Close</button>' +
          '</div>' +
        '</div>' +
        '<pre class="caa-report-body">' + esc(text) + '</pre>' +
      '</div>';
    const copyBtn = slot.querySelector('#caa-copy');
    const closeBtn = slot.querySelector('#caa-close');
    if (copyBtn) copyBtn.onclick = async () => {
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(text);
        else { const ta = slot.querySelector('.caa-report-body'); const sel = window.getSelection(); const rng = document.createRange(); rng.selectNodeContents(ta); sel.removeAllRanges(); sel.addRange(rng); document.execCommand('copy'); }
        ctx.toast('Report copied to clipboard', 'good');
      } catch (_) { ctx.toast('Select the report text to copy', 'bad'); }
    };
    if (closeBtn) closeBtn.onclick = () => { if (container.isConnected) slot.innerHTML = ''; };
    slot.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // ------------------------------ wiring -----------------------------------
  function wire(run, s, camp, posture) {
    const sel = container.querySelector('#caa-runsel');
    if (sel) sel.onchange = () => { selectedId = sel.value; render(); };
    const exp = container.querySelector('#caa-export');
    if (exp) exp.onclick = () => exportToGraph(run, s, camp, exp);
    const rep = container.querySelector('#caa-report');
    if (rep) rep.onclick = () => showReport(run, s, camp, posture);
  }

  render();
}

// --------------------------------- styles ----------------------------------
function styleBlock() {
  return '<style>' +
    '.caa-empty{text-align:center;padding:40px 20px}' +
    '.caa-empty h3{margin:0 0 6px}' +
    '.caa-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;flex-wrap:wrap}' +
    '.caa-head-l{min-width:0}' +
    '.caa-obj{margin:6px 0 0;font-size:.78rem;color:var(--mut)}' +
    '.caa-selwrap{display:flex;flex-direction:column;gap:4px;font-size:.66rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut)}' +
    '.caa-sel{background:var(--card);color:var(--txt);border:1px solid var(--line);border-radius:4px;padding:7px 10px;font-family:inherit;font-size:.82rem;min-width:190px}' +
    '.caa-scorewrap{display:grid;grid-template-columns:auto 1fr;gap:14px;margin:14px 0}' +
    '.caa-grade{display:flex;align-items:center;gap:16px;border-width:2px}' +
    '.caa-grade-g{font-size:3.2rem;font-weight:900;line-height:1}' +
    '.caa-grade-n{font-size:1.6rem;font-weight:800}' +
    '.caa-grade-n span{font-size:.8rem;font-weight:600;color:var(--mut)}' +
    '.caa-kpis{align-content:start}' +
    '.caa-heat{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin-top:12px}' +
    '.caa-cell{border:1px solid var(--line);border-radius:6px;padding:10px 12px;background:var(--card)}' +
    '.caa-cell-na{opacity:.55}' +
    '.caa-cell-top{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:8px}' +
    '.caa-cell-name{font-size:.76rem;font-weight:600}' +
    '.caa-cell-val{font-size:.74rem;font-weight:700;color:var(--mut)}' +
    '.caa-cell-bar{height:8px;border-radius:4px;background:color-mix(in srgb,var(--line) 60%,transparent);overflow:hidden}' +
    '.caa-cell-fill{height:100%;border-radius:4px;transition:width .3s}' +
    '.caa-gap-grid{grid-template-columns:repeat(auto-fit,minmax(300px,1fr));margin:14px 0}' +
    '.caa-gaps{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:6px}' +
    '.caa-gaps li{display:flex;align-items:baseline;gap:10px;padding:8px 10px;border:1px solid var(--line);border-radius:4px;font-size:.82rem}' +
    '.caa-gaps li.caa-none{color:var(--mut);border-style:dashed}' +
    '.caa-gap-t{font-weight:600;flex:1;min-width:0}' +
    '.caa-gap-a{color:var(--mut);font-size:.76rem}' +
    '.caa-gap-id{color:var(--mut);font-size:.72rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
    '.caa-tl{display:flex;flex-direction:column;gap:2px;margin-top:12px;position:relative}' +
    '.caa-tl-row{display:grid;grid-template-columns:64px 16px 1fr;align-items:center;gap:8px;padding:5px 0;font-size:.82rem}' +
    '.caa-tl-t{color:var(--mut);font-size:.72rem;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;text-align:right}' +
    '.caa-tl-dot{width:9px;height:9px;border-radius:50%;justify-self:center}' +
    '.caa-tl-atk .caa-tl-dot{background:#dc2626}' +
    '.caa-tl-def .caa-tl-dot{background:#2563eb}' +
    '.caa-tl-who{font-weight:800;font-size:.64rem;letter-spacing:.08em;color:#dc2626;margin-right:4px}' +
    '.caa-tl-who-def{color:#2563eb}' +
    '.caa-tl-target{color:var(--mut)}' +
    '.caa-tl-tag{font-size:.62rem;font-weight:700;letter-spacing:.04em;padding:1px 6px;border-radius:3px;margin-left:6px;text-transform:uppercase}' +
    '.caa-tl-det{background:color-mix(in srgb,#16a34a 18%,transparent);color:#16a34a}' +
    '.caa-tl-miss{background:color-mix(in srgb,#dc2626 18%,transparent);color:#dc2626}' +
    '.caa-tl-block{background:color-mix(in srgb,#2563eb 18%,transparent);color:#2563eb}' +
    '.caa-actions{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}' +
    '.caa-report{margin-top:14px}' +
    '.caa-report-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}' +
    '.caa-report-btns{display:flex;gap:8px}' +
    '.caa-report-body{margin:12px 0 0;padding:14px;background:var(--bg);border:1px solid var(--line);border-radius:6px;font-size:.76rem;line-height:1.5;white-space:pre-wrap;word-break:break-word;max-height:460px;overflow:auto;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:var(--txt)}' +
    '.caa-pt-head,.caa-pt-row{display:grid;grid-template-columns:28px 2.4fr 1.3fr 64px 1.6fr 88px;gap:10px;align-items:center}' +
    '.caa-pt-head{font-size:.62rem;letter-spacing:.06em;text-transform:uppercase;color:var(--mut);padding:0 10px 8px;margin-top:12px;border-bottom:1px solid var(--line)}' +
    '.caa-pt{display:flex;flex-direction:column;gap:4px;margin-top:6px}' +
    '.caa-pt-row{padding:7px 10px;border:1px solid var(--line);border-radius:4px;font-size:.78rem;background:var(--card)}' +
    '.caa-pt-row.caa-pt-blocked{border-left:3px solid #2563eb}' +
    '.caa-pt-row.caa-pt-detected{border-left:3px solid #16a34a}' +
    '.caa-pt-row.caa-pt-missed{border-left:3px solid #dc2626}' +
    '.caa-pt-i{color:var(--mut);font-variant-numeric:tabular-nums;font-size:.72rem}' +
    '.caa-pt-tech{min-width:0;font-weight:600;display:flex;flex-direction:column;gap:1px}' +
    '.caa-pt-id{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.72rem;color:var(--mut)}' +
    '.caa-pt-tac{font-size:.62rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}' +
    '.caa-pt-tgt{font-size:.74rem;color:var(--mut);min-width:0;display:inline-flex;align-items:center;gap:5px}' +
    '.caa-pt-cj{font-size:.54rem;font-weight:800;color:#d97706;border:1px solid #d97706;border-radius:3px;padding:0 4px}' +
    '.caa-pt-t{font-size:.72rem;color:var(--mut);font-variant-numeric:tabular-nums}' +
    '.caa-pt-sensor{font-size:.72rem;color:var(--txt);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}' +
    '.caa-none-txt{color:var(--mut)}' +
    '.caa-pt-status{text-align:right}' +
    '@media (max-width:720px){.caa-pt-head{display:none}' +
      '.caa-pt-row{grid-template-columns:22px 1fr auto;grid-auto-rows:min-content;row-gap:4px}' +
      '.caa-pt-tgt{grid-column:2/4}.caa-pt-t,.caa-pt-sensor{grid-column:2/4}.caa-pt-status{grid-column:3/4;grid-row:1}}' +
    '.caa-recs{list-style:none;margin:12px 0 0;padding:0;display:flex;flex-direction:column;gap:8px}' +
    '.caa-rec{display:flex;gap:12px;align-items:flex-start;padding:10px 12px;border:1px solid var(--line);border-radius:4px;background:var(--card)}' +
    '.caa-rec-critical{border-left:3px solid #dc2626}.caa-rec-high{border-left:3px solid #ea580c}' +
    '.caa-rec-medium{border-left:3px solid #d97706}.caa-rec-low{border-left:3px solid #16a34a}' +
    '.caa-rec-sev{font-size:.6rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;flex:0 0 auto;padding-top:2px;min-width:56px}' +
    '.caa-rec-body{display:flex;flex-direction:column;gap:3px;min-width:0}' +
    '.caa-rec-t{font-weight:700;font-size:.82rem}' +
    '.caa-rec-d{font-size:.76rem;color:var(--mut);line-height:1.45}' +
    '@media (max-width:640px){.caa-scorewrap{grid-template-columns:1fr}}' +
    '</style>';
}
