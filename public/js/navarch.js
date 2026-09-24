// navarch.js — NAVARCH flagship: Naval & maritime cyber-defense command console.
// Self-contained ES module. Pure vanilla JS, no imports, no network calls.
// All data simulated/hardcoded. Uses site design tokens + utility classes.

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function clamp(n, lo, hi) { return Math.max(lo, Math.min(hi, n)); }

function toRad(d) { return (d * Math.PI) / 180; }

// Haversine great-circle distance in nautical miles.
function haversineNm(lat1, lon1, lat2, lon2) {
  const R = 3440.065; // Earth radius in nautical miles
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a =
    Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) *
      Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

function badge(text, kind) {
  // kind: ok | warn | bad | info | mut
  const map = {
    ok: 'background:rgba(46,204,113,.14);color:#3ddc84;border-color:rgba(46,204,113,.35)',
    warn: 'background:rgba(241,196,15,.14);color:#f1c40f;border-color:rgba(241,196,15,.4)',
    bad: 'background:rgba(231,76,60,.15);color:#ff6b5e;border-color:rgba(231,76,60,.4)',
    info: 'background:rgba(52,152,219,.14);color:#5bb0f2;border-color:rgba(52,152,219,.4)',
    mut: 'background:var(--card2);color:var(--mut);border-color:var(--line)'
  };
  const style = map[kind] || map.mut;
  return `<span class="nv-badge" style="${style}">${esc(text)}</span>`;
}

// ---------------------------------------------------------------------------
// Static / simulated data
// ---------------------------------------------------------------------------

const SYSTEMS = ['ECDIS', 'Radar', 'Propulsion/IMS', 'Cargo/Ballast SCADA', 'VSAT', 'IBS'];

function randomPosture(seed) {
  const states = ['SECURE', 'SECURE', 'DEGRADED', 'EXPOSED'];
  return states[seed % states.length];
}

const FLEET = [
  { name: 'DDG-71 Ranger', cls: 'Destroyer', mmsi: '366982140', flag: 'US', status: 'UNDERWAY', readiness: 91 },
  { name: 'CVN Meridian', cls: 'Carrier', mmsi: '338771902', flag: 'US', status: 'UNDERWAY', readiness: 88 },
  { name: 'MV Atlas Crest', cls: 'Container', mmsi: '477553210', flag: 'HK', status: 'MOORED', readiness: 62 },
  { name: 'MT Nordic Falcon', cls: 'Tanker', mmsi: '257884001', flag: 'NO', status: 'UNDERWAY', readiness: 74 },
  { name: 'SSN Silent Tide', cls: 'Submarine', mmsi: '369104558', flag: 'US', status: 'DARK', readiness: 96 },
  { name: 'MV Cape Horizon', cls: 'Bulk Carrier', mmsi: '636019887', flag: 'LR', status: 'UNDERWAY', readiness: 55 },
  { name: 'MT Gulf Sentinel', cls: 'Tanker', mmsi: '470112003', flag: 'AE', status: 'MOORED', readiness: 68 },
  { name: 'MV Ghost Marlin', cls: 'Container', mmsi: '000445', flag: '??', status: 'DARK', readiness: 34 }
];

const CHOKEPOINTS = [
  { name: 'Strait of Hormuz', volume: 21, tension: 88, jamming: 72, piracy: 40, altRoute: 15, lat: 26.57, lon: 56.25 },
  { name: 'Strait of Malacca', volume: 24, tension: 55, jamming: 35, piracy: 65, altRoute: 30, lat: 2.50, lon: 101.50 },
  { name: 'Suez Canal', volume: 12, tension: 70, jamming: 45, piracy: 50, altRoute: 20, lat: 30.50, lon: 32.35 },
  { name: 'Bab-el-Mandeb', volume: 9, tension: 92, jamming: 60, piracy: 85, altRoute: 25, lat: 12.58, lon: 43.33 },
  { name: 'Panama Canal', volume: 14, tension: 30, jamming: 15, piracy: 20, altRoute: 40, lat: 9.08, lon: -79.68 },
  { name: 'Bosphorus', volume: 8, tension: 68, jamming: 55, piracy: 25, altRoute: 10, lat: 41.12, lon: 29.07 },
  { name: 'Strait of Gibraltar', volume: 10, tension: 40, jamming: 30, piracy: 22, altRoute: 55, lat: 35.95, lon: -5.60 },
  { name: 'Danish Straits', volume: 7, tension: 62, jamming: 68, piracy: 12, altRoute: 45, lat: 55.70, lon: 12.70 }
];

// Ports / navigational waypoints for the Route Risk Planner (name + lat/lon).
const WAYPOINTS = [
  { name: 'Rotterdam', lat: 51.95, lon: 4.14 },
  { name: 'Singapore', lat: 1.29, lon: 103.85 },
  { name: 'Jebel Ali (Dubai)', lat: 25.00, lon: 55.06 },
  { name: 'Shanghai', lat: 31.23, lon: 121.47 },
  { name: 'New York', lat: 40.67, lon: -74.04 },
  { name: 'Mumbai', lat: 18.94, lon: 72.84 },
  { name: 'Piraeus', lat: 37.94, lon: 23.64 },
  { name: 'Yokohama', lat: 35.44, lon: 139.64 },
  { name: 'Norfolk', lat: 36.94, lon: -76.31 },
  { name: 'Cape Town', lat: -33.90, lon: 18.42 }
];

const CABLES = [
  { name: 'SEA-ME-WE 6 (Red Sea segment)', status: 'AT-RISK', loiter: 3, note: 'High-density longhaul corridor; repeated anchor-drag incidents near Bab-el-Mandeb.' },
  { name: '2Africa (Gulf of Aden)', status: 'NOMINAL', loiter: 0, note: 'Redundant landing stations; carries the bulk of East-Africa transit traffic.' },
  { name: 'MAREA (North Atlantic)', status: 'NOMINAL', loiter: 1, note: 'Trans-Atlantic backbone; loitering fishing vessel flagged for monitoring.' },
  { name: 'Baltic Interconnector (BCS East-West)', status: 'DISRUPTED', loiter: 4, note: 'Physical damage consistent with dragged anchor; forensic investigation active.' },
  { name: 'JGA-S (Taiwan Strait)', status: 'AT-RISK', loiter: 2, note: 'Grey-zone pressure; multiple unregistered dredgers within exclusion zone.' },
  { name: 'FASTER (Trans-Pacific)', status: 'NOMINAL', loiter: 0, note: 'Diverse routing; primary US-Japan capacity path, no current anomalies.' }
];

const GNSS_INDICATORS = [
  { key: 'spoof', label: 'GNSS Spoofing Confidence', unit: '%', normal: 8, alarm: 87, mit: 'Cross-check GPS fix against radar ranges, celestial and inertial (INS). Treat sudden position jumps as hostile until proven.' },
  { key: 'jam', label: 'GPS Jamming Level', unit: 'dB', normal: 4, alarm: 41, mit: 'Switch to backup PNT (eLoran), reduce dependence on GPS-fed autopilot, log jamming bearing for reporting.' },
  { key: 'ecdis', label: 'ECDIS Chart Integrity (checksum)', unit: '', normal: 100, alarm: 62, mit: 'Verify ENC digital signatures (S-63), revert to last-known-good chart cell, keep paper backup plotted.' },
  { key: 'diverge', label: 'Gyro / AIS Position Divergence', unit: 'nm', normal: 0.1, alarm: 6.4, mit: 'Trust gyro/INS over AIS-derived position; AIS is unauthenticated and trivially spoofed.' },
  { key: 'eloran', label: 'Backup PNT (eLoran) Availability', unit: '%', normal: 100, alarm: 100, mit: 'Confirm eLoran receiver health BEFORE a GPS denial event; it is the primary fallback.' }
];

const EMCON_LEVELS = {
  ALPHA: { desc: 'Full emission silence. All active emitters secured for maximum stealth. Situational awareness relies on passive sensors only.', emitters: { Radar: false, VSAT: false, AIS: false, 'HF/VHF': false, IFF: false } },
  BRAVO: { desc: 'Restricted emissions. Passive-first posture; only encrypted low-probability-of-intercept links authorized intermittently.', emitters: { Radar: false, VSAT: true, AIS: false, 'HF/VHF': false, IFF: true } },
  CHARLIE: { desc: 'Selective emissions. Navigation and safety emitters active; tactical radar minimized to reduce electronic signature.', emitters: { Radar: true, VSAT: true, AIS: false, 'HF/VHF': true, IFF: true } },
  UNRESTRICTED: { desc: 'Unrestricted emissions. Full situational awareness and connectivity; maximum detectability. Peacetime / high-traffic transit posture.', emitters: { Radar: true, VSAT: true, AIS: true, 'HF/VHF': true, IFF: true } }
};

const AIS_SAMPLE_CLEAN =
`366982140,25.1000,55.2000,12.4,090,2026-09-22T10:00:00Z
366982140,25.1010,55.2400,12.4,090,2026-09-22T10:10:00Z
477553210,1.2600,103.8200,0.0,000,2026-09-22T10:00:00Z
477553210,1.2601,103.8201,0.0,000,2026-09-22T10:12:00Z
257884001,59.9000,10.7300,9.8,045,2026-09-22T10:00:00Z
257884001,59.9200,10.7600,9.8,045,2026-09-22T10:15:00Z`;

const AIS_SAMPLE_SPOOFED =
`366982140,25.1000,55.2000,12.0,090,2026-09-22T10:00:00Z
366982140,26.9000,56.9000,12.0,090,2026-09-22T10:05:00Z
477553210,1.2600,103.8200,0.2,000,2026-09-22T10:00:00Z
477553210,1.5900,104.1100,0.2,000,2026-09-22T10:08:00Z
636019887,10.0000,65.0000,14.0,270,2026-09-22T10:00:00Z
636019887,10.0100,64.5000,14.0,270,2026-09-22T10:02:00Z
00445,25.5000,55.5000,8.0,180,2026-09-22T10:00:00Z
636019887,48.0000,-30.0000,14.0,270,2026-09-22T10:03:00Z
257884001,199.0000,10.7300,9.8,045,2026-09-22T10:00:00Z`;

// ---------------------------------------------------------------------------
// AIS integrity engine (real detection logic)
// ---------------------------------------------------------------------------

function parseAis(text) {
  const rows = [];
  const errors = [];
  text.split(/\r?\n/).forEach((line, i) => {
    const raw = line.trim();
    if (!raw) return;
    const p = raw.split(',').map(x => x.trim());
    if (p.length < 6) {
      errors.push({ line: i + 1, raw, why: 'Malformed record: expected 6 comma-separated fields (MMSI,LAT,LON,SOG,COG,TIMESTAMP).' });
      return;
    }
    const [mmsi, latS, lonS, sogS, cogS, ts] = p;
    const lat = parseFloat(latS);
    const lon = parseFloat(lonS);
    const sog = parseFloat(sogS);
    const t = Date.parse(ts);
    rows.push({ mmsi, lat, lon, sog, cog: cogS, ts, tMs: isNaN(t) ? null : t, line: i + 1, raw });
  });
  return { rows, errors };
}

function scanAis(text) {
  const { rows, errors } = parseAis(text);
  const findings = [];

  // Per-record validity checks.
  rows.forEach(r => {
    if (!/^\d{9}$/.test(r.mmsi)) {
      findings.push({
        sev: 'HIGH', mmsi: r.mmsi, line: r.line, type: 'Impossible MMSI',
        detail: `MMSI "${r.mmsi}" is not a valid 9-digit maritime identity — likely fabricated or transmitter misconfiguration.`
      });
    }
    if (isNaN(r.lat) || isNaN(r.lon) || Math.abs(r.lat) > 90 || Math.abs(r.lon) > 180) {
      findings.push({
        sev: 'HIGH', mmsi: r.mmsi, line: r.line, type: 'Impossible coordinates',
        detail: `Position (${isNaN(r.lat) ? '?' : r.lat}, ${isNaN(r.lon) ? '?' : r.lon}) is out of range or on land — geometrically invalid.`
      });
    }
  });

  // Group by MMSI, order by timestamp.
  const groups = {};
  rows.forEach(r => {
    if (isNaN(r.lat) || isNaN(r.lon) || Math.abs(r.lat) > 90 || Math.abs(r.lon) > 180) return;
    (groups[r.mmsi] = groups[r.mmsi] || []).push(r);
  });

  Object.keys(groups).forEach(mmsi => {
    const list = groups[mmsi].slice().sort((a, b) => (a.tMs || 0) - (b.tMs || 0));

    for (let i = 1; i < list.length; i++) {
      const a = list[i - 1], b = list[i];
      const dist = haversineNm(a.lat, a.lon, b.lat, b.lon);
      const dtHr = (a.tMs != null && b.tMs != null) ? (b.tMs - a.tMs) / 3600000 : null;

      // (a) impossible speed / teleport
      if (dtHr != null && dtHr > 0) {
        const impSpeed = dist / dtHr; // knots
        const cap = Math.max((isNaN(b.sog) ? 0 : b.sog) * 3, 60);
        if (impSpeed > cap) {
          findings.push({
            sev: 'HIGH', mmsi, line: b.line, type: 'Position jump / teleport',
            detail: `Implied speed ${impSpeed.toFixed(1)} kn over ${dist.toFixed(1)} nm in ${(dtHr * 60).toFixed(0)} min far exceeds reported SOG (${isNaN(b.sog) ? '?' : b.sog} kn). Classic spoofed/injected track.`
          });
        }
      }

      // (b) speed/position mismatch — SOG ~0 but moved
      if (!isNaN(b.sog) && b.sog < 0.5 && dist > 1) {
        findings.push({
          sev: 'MED', mmsi, line: b.line, type: 'Speed/position mismatch',
          detail: `Reported SOG ${b.sog} kn (near stationary) yet position moved ${dist.toFixed(1)} nm since prior report — telemetry inconsistent.`
        });
      }

      // (c) duplicate MMSI — same window, far apart, tiny time delta
      if (dtHr != null && dtHr >= 0 && dtHr < 0.1 && dist > 50) {
        findings.push({
          sev: 'HIGH', mmsi, line: b.line, type: 'Duplicate MMSI',
          detail: `Same MMSI reporting from two positions ${dist.toFixed(0)} nm apart within ${(dtHr * 60).toFixed(1)} min — identity is being transmitted by more than one platform.`
        });
      }
    }
  });

  errors.forEach(e => findings.push({ sev: 'MED', mmsi: '-', line: e.line, type: 'Malformed record', detail: e.why }));

  const sevOrder = { HIGH: 0, MED: 1, LOW: 2 };
  findings.sort((a, b) => (sevOrder[a.sev] - sevOrder[b.sev]) || (a.line - b.line));
  return { findings, count: rows.length + errors.length, tracks: Object.keys(groups).length };
}

// ---------------------------------------------------------------------------
// Chokepoint risk scoring
// ---------------------------------------------------------------------------

function chokepointRisk(c, tensionMult, jammingMult) {
  const tension = clamp(c.tension * tensionMult, 0, 100);
  const jamming = clamp(c.jamming * jammingMult, 0, 100);
  // Weighted: tension + jamming + piracy + throughput exposure, reduced by alt routes.
  const throughput = clamp(c.volume * 3.2, 0, 100);
  let score =
    tension * 0.32 +
    jamming * 0.24 +
    c.piracy * 0.18 +
    throughput * 0.16 -
    c.altRoute * 0.22;
  score = clamp(Math.round(score + 25), 0, 100);
  let band = 'GUARDED', kind = 'ok';
  if (score >= 70) { band = 'HIGH'; kind = 'bad'; }
  else if (score >= 45) { band = 'ELEVATED'; kind = 'warn'; }
  return { score, band, kind };
}

// ---------------------------------------------------------------------------
// Route planning (reuses haversineNm + chokepointRisk)
// ---------------------------------------------------------------------------

// Build a transit: origin -> the chokepoints that lie roughly on the corridor
// (low detour ratio), ordered by distance from origin -> destination.
function buildRoute(origin, dest, tensionMult, jammingMult) {
  const direct = haversineNm(origin.lat, origin.lon, dest.lat, dest.lon);
  const between = CHOKEPOINTS
    .filter(c => typeof c.lat === 'number' && typeof c.lon === 'number')
    .map(c => {
      const fromO = haversineNm(origin.lat, origin.lon, c.lat, c.lon);
      const toD = haversineNm(c.lat, c.lon, dest.lat, dest.lon);
      return { c, fromO, detour: fromO + toD };
    })
    .filter(x => x.detour <= direct * 1.35 + 150) // on-corridor if barely a detour
    .sort((a, b) => a.fromO - b.fromO)
    .map(x => x.c);

  const nodes = [
    { name: origin.name, lat: origin.lat, lon: origin.lon, choke: null },
    ...between.map(c => ({ name: c.name, lat: c.lat, lon: c.lon, choke: c })),
    { name: dest.name, lat: dest.lat, lon: dest.lon, choke: null }
  ];

  const legs = [];
  let total = 0;
  for (let i = 1; i < nodes.length; i++) {
    const a = nodes[i - 1], b = nodes[i];
    const dist = haversineNm(a.lat, a.lon, b.lat, b.lon);
    total += dist;
    const chk = b.choke || a.choke;
    const risk = chk ? chokepointRisk(chk, tensionMult, jammingMult)
                     : { score: 20, band: 'GUARDED', kind: 'ok' }; // open-water baseline
    legs.push({ from: a.name, to: b.name, dist, risk });
  }

  // Aggregate route risk weighted by leg distance.
  const agg = total > 0
    ? Math.round(legs.reduce((s, l) => s + l.risk.score * l.dist, 0) / total)
    : 0;

  // Single highest-risk chokepoint on the route.
  let worst = null;
  between.forEach(c => {
    const r = chokepointRisk(c, tensionMult, jammingMult);
    if (!worst || r.score > worst.r.score) worst = { c, r };
  });

  return { nodes, legs, total, agg, worst, between, direct };
}

// Recommended EMCON posture + one-line advisory keyed to aggregate route risk.
function routePosture(agg) {
  if (agg >= 65) return {
    emcon: 'BRAVO', kind: 'bad',
    advisory: 'Composite route risk is HIGH. Tighten to EMCON BRAVO/ALPHA, run hardened PNT with eLoran fallback, and escort merchant traffic through the flagged chokepoint.'
  };
  if (agg >= 45) return {
    emcon: 'CHARLIE', kind: 'warn',
    advisory: 'Elevated route risk. Hold EMCON CHARLIE, pre-brief GNSS-spoofing indicators, and stagger transit timing away from peak congestion.'
  };
  return {
    emcon: 'UNRESTRICTED', kind: 'ok',
    advisory: 'Route risk is manageable. Maintain unrestricted emissions for full situational awareness; keep watching chokepoint drivers for change.'
  };
}

// ---------------------------------------------------------------------------
// Style injection (scoped .nv-*)
// ---------------------------------------------------------------------------

function injectStyle() {
  if (document.getElementById('nv-style')) return;
  const s = document.createElement('style');
  s.id = 'nv-style';
  s.textContent = `
  .nv-wrap{width:100%}
  .nv-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:14px 0 16px;border-bottom:1px solid var(--line);padding-bottom:10px}
  .nv-tab{background:var(--card2);color:var(--mut);border:1px solid var(--line);border-radius:8px;padding:8px 14px;cursor:pointer;font-size:13px;font-weight:600;letter-spacing:.02em}
  .nv-tab:hover{color:var(--txt);border-color:var(--acc)}
  .nv-tab.active{background:var(--acc);color:#04121a;border-color:var(--acc)}
  .nv-badge{display:inline-block;font-size:10.5px;font-weight:700;letter-spacing:.06em;padding:2px 7px;border-radius:5px;border:1px solid var(--line);text-transform:uppercase}
  .nv-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
  .nv-grid.wide{grid-template-columns:repeat(auto-fill,minmax(300px,1fr))}
  .nv-vessel{cursor:pointer;transition:border-color .15s,transform .1s}
  .nv-vessel:hover{border-color:var(--acc);transform:translateY(-1px)}
  .nv-vessel.sel{border-color:var(--acc);box-shadow:0 0 0 1px var(--acc) inset}
  .nv-row{display:flex;justify-content:space-between;align-items:center;gap:8px;padding:6px 0;border-bottom:1px solid var(--line);font-size:13px}
  .nv-row:last-child{border-bottom:none}
  .nv-table{width:100%;border-collapse:collapse;font-size:12.5px}
  .nv-table th,.nv-table td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
  .nv-table th{color:var(--mut);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.05em}
  .nv-meter{height:7px;border-radius:4px;background:var(--card2);overflow:hidden;margin-top:6px}
  .nv-meter>i{display:block;height:100%;border-radius:4px}
  .nv-ta{width:100%;min-height:150px;background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:10px;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12.5px;resize:vertical}
  .nv-mono{font-family:ui-monospace,Menlo,Consolas,monospace}
  .nv-controls{display:flex;flex-wrap:wrap;gap:14px;align-items:center;margin:10px 0}
  .nv-controls label{font-size:12px;color:var(--mut);display:flex;flex-direction:column;gap:4px;min-width:180px}
  .nv-controls input[type=range]{accent-color:var(--acc)}
  .nv-emitter{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:var(--card2);margin-bottom:8px}
  .nv-score{font-size:30px;font-weight:800;line-height:1}
  .nv-note{font-size:12px;color:var(--mut);margin-top:8px;line-height:1.5}
  .nv-kv{font-size:12px;color:var(--mut);display:flex;justify-content:space-between;padding:3px 0}
  .nv-kv b{color:var(--txt);font-weight:600}
  .nv-select{background:var(--bg);color:var(--txt);border:1px solid var(--line);border-radius:8px;padding:7px 10px;font-size:13px;min-width:180px}
  .nv-select:focus{outline:none;border-color:var(--acc)}
  .nv-check{display:flex;align-items:center;gap:8px;padding:8px 6px;border-bottom:1px solid var(--line);cursor:pointer;font-size:13px}
  .nv-check:last-child{border-bottom:none}
  .nv-check input{accent-color:var(--acc);width:15px;height:15px;flex:none}
  `;
  document.head.appendChild(s);
}

// ---------------------------------------------------------------------------
// Panel renderers
// ---------------------------------------------------------------------------

function panelFleet(host) {
  const underway = FLEET.filter(v => v.status === 'UNDERWAY').length;
  const dark = FLEET.filter(v => v.status === 'DARK').length;
  const avg = Math.round(FLEET.reduce((a, v) => a + v.readiness, 0) / FLEET.length);

  host.innerHTML = `
    <div class="stat-row" style="display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px">
      <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">VESSELS</div><div class="nv-score">${FLEET.length}</div></div>
      <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">UNDERWAY</div><div class="nv-score" style="color:var(--acc)">${underway}</div></div>
      <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">DARK SHIPS</div><div class="nv-score" style="color:#ff6b5e">${dark}</div></div>
      <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">AVG READINESS</div><div class="nv-score">${avg}</div></div>
    </div>
    <div style="display:grid;grid-template-columns:1.3fr 1fr;gap:14px" class="nv-fleet-layout">
      <div><div class="nv-grid" id="nv-fleet-grid"></div></div>
      <div><div class="card panel" id="nv-fleet-detail" style="padding:16px">${fleetOverviewHtml()}</div></div>
    </div>`;

  const grid = host.querySelector('#nv-fleet-grid');
  const statusKind = { UNDERWAY: 'ok', MOORED: 'info', DARK: 'bad' };
  grid.innerHTML = FLEET.map((v, i) => {
    const rk = v.readiness >= 80 ? 'ok' : v.readiness >= 60 ? 'warn' : 'bad';
    const col = v.readiness >= 80 ? '#3ddc84' : v.readiness >= 60 ? '#f1c40f' : '#ff6b5e';
    return `<div class="card nv-vessel" data-i="${i}" style="padding:12px">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:6px">
        <b style="font-size:13.5px">${esc(v.name)}</b>${badge(v.status, statusKind[v.status])}
      </div>
      <div class="muted" style="font-size:11.5px;margin:4px 0">${esc(v.cls)} · ${esc(v.flag)} · MMSI ${esc(v.mmsi)}</div>
      <div class="nv-kv"><span>Cyber readiness</span><b style="color:${col}">${v.readiness}/100</b></div>
      <div class="nv-meter"><i style="width:${v.readiness}%;background:${col}"></i></div>
    </div>`;
  }).join('');

  grid.querySelectorAll('.nv-vessel').forEach(el => {
    el.addEventListener('click', () => {
      grid.querySelectorAll('.nv-vessel').forEach(x => x.classList.remove('sel'));
      el.classList.add('sel');
      showVesselDetail(host, FLEET[+el.dataset.i]);
    });
  });
}

// Default right-hand panel: a plain-language overview so the space isn't empty
// and a newcomer immediately understands what this board is for.
function fleetOverviewHtml() {
  const avg = Math.round(FLEET.reduce((a, v) => a + v.readiness, 0) / FLEET.length);
  const col = avg >= 80 ? '#3ddc84' : avg >= 60 ? '#f1c40f' : '#ff6b5e';
  const worst = FLEET.slice().sort((a, b) => a.readiness - b.readiness)[0];
  const dark = FLEET.filter(v => v.status === 'DARK');
  return `
    <div class="pg-h2" style="font-size:14px;margin:0 0 4px">Fleet posture</div>
    <p class="muted" style="font-size:12.5px;line-height:1.55;margin:0 0 12px">
      Every hull you are monitoring and the cyber health of its onboard systems.
      <b>Click any vessel card on the left</b> to inspect its ECDIS, radar, propulsion,
      cargo/ballast SCADA and satellite links.</p>
    <div class="nv-kv"><span>Fleet-wide readiness</span><b style="color:${col}">${avg}/100</b></div>
    <div class="nv-meter" style="margin-bottom:12px"><i style="width:${avg}%;background:${col}"></i></div>
    <div class="nv-kv"><span>Most at risk</span><b style="color:#ff6b5e">${esc(worst.name)} · ${worst.readiness}/100</b></div>
    <div class="nv-kv"><span>Going dark (AIS off)</span><b>${dark.length ? dark.map(v => esc(v.name)).join(', ') : 'None'}</b></div>
    <div class="pg-h2" style="font-size:12px;margin:14px 0 6px">HOW TO READ POSTURE</div>
    <div class="nv-row"><span>Systems locked down, patched, monitored</span>${badge('SECURE', 'ok')}</div>
    <div class="nv-row"><span>Weakness present — needs attention</span>${badge('DEGRADED', 'warn')}</div>
    <div class="nv-row"><span>Actively exploitable / unprotected</span>${badge('EXPOSED', 'bad')}</div>
    <div class="nv-note">A "dark ship" has switched off its AIS transponder — sometimes routine, often a sign of sanctions evasion, smuggling, or an attempt to hide a hijacked or spoofed track.</div>`;
}

function showVesselDetail(host, v) {
  const box = host.querySelector('#nv-fleet-detail');
  const pk = { SECURE: 'ok', DEGRADED: 'warn', EXPOSED: 'bad' };
  const seed = parseInt(v.mmsi.replace(/\D/g, '').slice(-3) || '0', 10);
  const rows = SYSTEMS.map((sys, i) => {
    const posture = v.status === 'DARK' && sys === 'VSAT' ? 'DEGRADED' : randomPosture(seed + i * 3 + v.name.length);
    return `<div class="nv-row"><span>${esc(sys)}</span>${badge(posture, pk[posture])}</div>`;
  }).join('');
  box.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:8px">
      <b style="font-size:15px">${esc(v.name)}</b>${badge(v.status, v.status === 'DARK' ? 'bad' : 'ok')}
    </div>
    <div class="nv-kv"><span>Class</span><b>${esc(v.cls)}</b></div>
    <div class="nv-kv"><span>Flag state</span><b>${esc(v.flag)}</b></div>
    <div class="nv-kv"><span>MMSI</span><b class="nv-mono">${esc(v.mmsi)}</b></div>
    <div class="nv-kv" style="margin-bottom:8px"><span>Cyber readiness</span><b>${v.readiness}/100</b></div>
    <div class="pg-h2" style="font-size:13px;margin:10px 0 4px">ONBOARD SYSTEMS</div>
    ${rows}
    <div class="nv-note">OT/IT convergence on modern hulls means a compromised VSAT or ECDIS can cascade into propulsion and cargo control. Segment IT from OT and monitor the bridge network.</div>`;
}

function panelAis(host) {
  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">AIS Integrity Scanner</div>
    <div class="pg-sub" style="margin-bottom:10px">AIS is unauthenticated and broadcast in the clear — trivially spoofed. Paste position reports and run consecutive-fix analysis to expose fabricated tracks.</div>
    <div class="nv-note" style="margin:0 0 8px">New here? Click <b>Load spoofed sample</b> then <b>Scan</b> to watch the detector catch faked ship tracks — teleporting vessels, cloned identities and impossible speeds.</div>
    <div class="muted" style="font-size:11.5px;margin-bottom:6px">Format: MMSI,LAT,LON,SOG(kn),COG,TIMESTAMP — one report per line</div>
    <textarea class="nv-ta" id="nv-ais-in">${esc(AIS_SAMPLE_CLEAN)}</textarea>
    <div style="display:flex;flex-wrap:wrap;gap:8px;margin:10px 0">
      <button class="btn sm" id="nv-ais-scan">SCAN</button>
      <button class="btn ghost sm" id="nv-ais-spoof">LOAD SPOOFED SAMPLE</button>
      <button class="btn ghost sm" id="nv-ais-clean">LOAD CLEAN SAMPLE</button>
    </div>
    <div id="nv-ais-out"></div>`;

  const ta = host.querySelector('#nv-ais-in');
  const out = host.querySelector('#nv-ais-out');

  function run() {
    const res = scanAis(ta.value);
    const sk = { HIGH: 'bad', MED: 'warn', LOW: 'info' };
    const summary = `<div class="nv-controls" style="margin-bottom:8px">
      <span>${badge(res.count + ' records', 'mut')}</span>
      <span>${badge(res.tracks + ' tracks', 'info')}</span>
      <span>${badge(res.findings.length + ' findings', res.findings.length ? 'bad' : 'ok')}</span>
    </div>`;
    if (!res.findings.length) {
      out.innerHTML = summary + `<div class="card panel" style="padding:14px">${badge('CLEAN', 'ok')} No integrity anomalies detected across consecutive fixes.</div>`;
      return;
    }
    const rows = res.findings.map(f => `<tr>
      <td>${badge(f.sev, sk[f.sev] || 'mut')}</td>
      <td class="nv-mono">${esc(f.mmsi)}</td>
      <td>${f.line}</td>
      <td><b>${esc(f.type)}</b><br><span class="muted" style="font-size:11.5px">${esc(f.detail)}</span></td>
    </tr>`).join('');
    out.innerHTML = summary + `<div class="card panel" style="padding:0;overflow-x:auto">
      <table class="nv-table"><thead><tr><th>Severity</th><th>MMSI</th><th>Line</th><th>Finding</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  host.querySelector('#nv-ais-scan').addEventListener('click', run);
  host.querySelector('#nv-ais-spoof').addEventListener('click', () => { ta.value = AIS_SAMPLE_SPOOFED; run(); });
  host.querySelector('#nv-ais-clean').addEventListener('click', () => { ta.value = AIS_SAMPLE_CLEAN; run(); });
  run();
}

function panelChokepoints(host) {
  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">Chokepoint Risk Matrix</div>
    <div class="pg-sub" style="margin-bottom:8px">Composite risk across the world's strategic maritime chokepoints. Adjust global drivers to recompute live.</div>
    <div class="nv-controls">
      <label>Global tension multiplier <span id="nv-cp-tv">1.00x</span>
        <input type="range" id="nv-cp-tension" min="50" max="150" value="100"></label>
      <label>Jamming activity multiplier <span id="nv-cp-jv">1.00x</span>
        <input type="range" id="nv-cp-jam" min="50" max="150" value="100"></label>
    </div>
    <div class="nv-grid wide" id="nv-cp-grid"></div>`;

  const tSl = host.querySelector('#nv-cp-tension');
  const jSl = host.querySelector('#nv-cp-jam');
  const grid = host.querySelector('#nv-cp-grid');

  function draw() {
    const tm = +tSl.value / 100, jm = +jSl.value / 100;
    host.querySelector('#nv-cp-tv').textContent = tm.toFixed(2) + 'x';
    host.querySelector('#nv-cp-jv').textContent = jm.toFixed(2) + 'x';
    grid.innerHTML = CHOKEPOINTS.map(c => {
      const r = chokepointRisk(c, tm, jm);
      const col = r.kind === 'bad' ? '#ff6b5e' : r.kind === 'warn' ? '#f1c40f' : '#3ddc84';
      return `<div class="card" style="padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start">
          <b style="font-size:14px">${esc(c.name)}</b>${badge(r.band, r.kind)}
        </div>
        <div style="display:flex;align-items:baseline;gap:8px;margin:8px 0">
          <span class="nv-score" style="color:${col}">${r.score}</span><span class="muted">/100 risk</span>
        </div>
        <div class="nv-meter"><i style="width:${r.score}%;background:${col}"></i></div>
        <div class="nv-kv" style="margin-top:8px"><span>Daily transit</span><b>${c.volume}M bbl-eq</b></div>
        <div class="nv-kv"><span>GPS-jamming reports</span><b>${c.jamming}</b></div>
        <div class="nv-kv"><span>Piracy index</span><b>${c.piracy}</b></div>
        <div class="nv-kv"><span>Alt-route availability</span><b>${c.altRoute}%</b></div>
      </div>`;
    }).join('');
  }
  tSl.addEventListener('input', draw);
  jSl.addEventListener('input', draw);
  draw();
}

function panelGnss(host) {
  let alarm = false;
  host.innerHTML = `
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
      <div>
        <div class="pg-h2" style="font-size:15px">GNSS / ECDIS Threat Console</div>
        <div class="pg-sub">Navigation-integrity board. GPS/GNSS is the single most spoofable dependency at sea.</div>
      </div>
      <button class="btn sm" id="nv-gnss-sim">SIMULATE SPOOFING EVENT</button>
    </div>
    <div class="nv-grid wide" id="nv-gnss-grid" style="margin-top:12px"></div>`;

  const grid = host.querySelector('#nv-gnss-grid');
  function draw() {
    grid.innerHTML = GNSS_INDICATORS.map(ind => {
      const v = alarm ? ind.alarm : ind.normal;
      // spoof/jam/diverge: higher=worse. ecdis: checksum. eloran: fallback readiness.
      let stateKind, stateTxt;
      if (ind.key === 'spoof' || ind.key === 'jam' || ind.key === 'diverge') {
        stateKind = alarm ? 'bad' : 'ok';
        stateTxt = alarm ? 'ALARM' : 'NOMINAL';
      } else if (ind.key === 'ecdis') {
        stateKind = alarm ? 'warn' : 'ok';
        stateTxt = alarm ? 'CHECKSUM FAIL' : 'VERIFIED';
      } else {
        stateKind = alarm ? 'warn' : 'ok';
        stateTxt = alarm ? 'RELYING (PRIMARY DOWN)' : 'READY';
      }
      return `<div class="card" style="padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:6px">
          <b style="font-size:13.5px">${esc(ind.label)}</b>${badge(stateTxt, stateKind)}
        </div>
        <div style="display:flex;align-items:baseline;gap:6px;margin:8px 0">
          <span class="nv-score" style="font-size:24px">${v}</span><span class="muted">${esc(ind.unit)}</span>
        </div>
        <div class="nv-note"><b style="color:var(--txt)">MITIGATION:</b> ${esc(ind.mit)}</div>
      </div>`;
    }).join('');
  }
  const btn = host.querySelector('#nv-gnss-sim');
  btn.addEventListener('click', () => {
    alarm = !alarm;
    btn.textContent = alarm ? 'CLEAR ALARM STATE' : 'SIMULATE SPOOFING EVENT';
    draw();
  });
  draw();
}

function panelCables(host) {
  const sk = { NOMINAL: 'ok', 'AT-RISK': 'warn', DISRUPTED: 'bad' };
  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">Subsea Cable Watch</div>
    <div class="pg-sub" style="margin-bottom:6px">Roughly 99% of intercontinental data traverses undersea cables. Cutting or tapping a segment is a high-leverage grey-zone action — physical destruction, traffic interception, or capacity denial.</div>
    <div class="nv-grid wide" style="margin-top:10px">
      ${CABLES.map(c => `<div class="card" style="padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:6px">
          <b style="font-size:13.5px">${esc(c.name)}</b>${badge(c.status, sk[c.status])}
        </div>
        <div class="nv-kv" style="margin-top:8px"><span>Vessel-loitering alerts</span><b style="color:${c.loiter > 2 ? '#ff6b5e' : c.loiter > 0 ? '#f1c40f' : '#3ddc84'}">${c.loiter}</b></div>
        <div class="nv-note">${esc(c.note)}</div>
      </div>`).join('')}
    </div>`;
}

function panelEmcon(host) {
  const keys = Object.keys(EMCON_LEVELS);
  let cur = 'CHARLIE';
  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">EMCON Posture</div>
    <div class="pg-sub" style="margin-bottom:10px">Emission Control governs which emitters radiate. Every active emitter trades stealth for situational awareness — the core electronic-warfare dilemma.</div>
    <div class="nv-tabs" id="nv-emcon-sel" style="border:none;padding:0;margin-bottom:12px">
      ${keys.map(k => `<button class="nv-tab" data-k="${k}">${esc(k)}</button>`).join('')}
    </div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px" class="nv-fleet-layout">
      <div class="card panel" style="padding:14px" id="nv-emcon-emitters"></div>
      <div class="card panel" style="padding:14px" id="nv-emcon-doctrine"></div>
    </div>`;

  const selWrap = host.querySelector('#nv-emcon-sel');
  function draw() {
    selWrap.querySelectorAll('.nv-tab').forEach(b => b.classList.toggle('active', b.dataset.k === cur));
    const lvl = EMCON_LEVELS[cur];
    host.querySelector('#nv-emcon-emitters').innerHTML =
      `<div class="pg-h2" style="font-size:13px;margin-bottom:8px">EMITTER STATE — EMCON ${esc(cur)}</div>` +
      Object.keys(lvl.emitters).map(em => {
        const on = lvl.emitters[em];
        return `<div class="nv-emitter"><span>${esc(em)}</span>${badge(on ? 'ON' : 'OFF', on ? 'ok' : 'mut')}</div>`;
      }).join('');
    const activeCount = Object.values(lvl.emitters).filter(Boolean).length;
    host.querySelector('#nv-emcon-doctrine').innerHTML = `
      <div class="pg-h2" style="font-size:13px;margin-bottom:8px">DOCTRINE</div>
      <div style="font-size:13px;line-height:1.6">${esc(lvl.desc)}</div>
      <div class="nv-kv" style="margin-top:12px"><span>Active emitters</span><b>${activeCount} / 5</b></div>
      <div class="nv-kv"><span>Signature</span><b>${activeCount === 0 ? 'MINIMAL' : activeCount >= 4 ? 'HIGH' : 'MODERATE'}</b></div>
      <div class="nv-kv"><span>Situational awareness</span><b>${activeCount === 0 ? 'PASSIVE ONLY' : activeCount >= 4 ? 'FULL' : 'PARTIAL'}</b></div>
      <div class="nv-note">Tighter EMCON reduces the probability of detection and targeting but blinds own-force sensors and severs off-hull connectivity. Commanders set the level to the threat.</div>`;
  }
  selWrap.querySelectorAll('.nv-tab').forEach(b => b.addEventListener('click', () => { cur = b.dataset.k; draw(); }));
  draw();
}

function panelRoute(host) {
  const opts = WAYPOINTS.map((w, i) => `<option value="${i}">${esc(w.name)}</option>`).join('');
  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">Route Risk Planner</div>
    <div class="pg-sub" style="margin-bottom:8px">Plot a transit between ports; the planner threads it through the strategic chokepoints on the corridor and scores composite risk leg by leg. Adjust global drivers to recompute live.</div>
    <div class="nv-controls">
      <label>Origin
        <select class="nv-select" id="nv-rt-origin">${opts}</select></label>
      <label>Destination
        <select class="nv-select" id="nv-rt-dest">${opts}</select></label>
      <label>Geopolitical tension <span id="nv-rt-tv">1.00x</span>
        <input type="range" id="nv-rt-tension" min="50" max="150" value="100"></label>
      <label>GNSS jamming <span id="nv-rt-jv">1.00x</span>
        <input type="range" id="nv-rt-jam" min="50" max="150" value="100"></label>
    </div>
    <div id="nv-rt-out"></div>`;

  const oSel = host.querySelector('#nv-rt-origin');
  const dSel = host.querySelector('#nv-rt-dest');
  const tSl = host.querySelector('#nv-rt-tension');
  const jSl = host.querySelector('#nv-rt-jam');
  const out = host.querySelector('#nv-rt-out');
  oSel.value = '0'; dSel.value = '1'; // Rotterdam -> Singapore

  function draw() {
    const tm = +tSl.value / 100, jm = +jSl.value / 100;
    host.querySelector('#nv-rt-tv').textContent = tm.toFixed(2) + 'x';
    host.querySelector('#nv-rt-jv').textContent = jm.toFixed(2) + 'x';
    const origin = WAYPOINTS[+oSel.value], dest = WAYPOINTS[+dSel.value];
    if (origin === dest) {
      out.innerHTML = `<div class="card panel" style="padding:14px">${badge('SELECT', 'info')} Origin and destination are the same port — choose two different endpoints.</div>`;
      return;
    }
    const rt = buildRoute(origin, dest, tm, jm);
    const post = routePosture(rt.agg);
    const aggCol = post.kind === 'bad' ? '#ff6b5e' : post.kind === 'warn' ? '#f1c40f' : '#3ddc84';
    const legRows = rt.legs.map(l => `<tr>
      <td>${esc(l.from)}</td><td>${esc(l.to)}</td>
      <td class="nv-mono">${Math.round(l.dist)}</td>
      <td>${badge(l.risk.band, l.risk.kind)} <span class="muted">${l.risk.score}</span></td>
    </tr>`).join('');
    out.innerHTML = `
      <div class="stat-row" style="display:flex;flex-wrap:wrap;gap:10px;margin:6px 0 14px">
        <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">TOTAL DISTANCE</div><div class="nv-score" style="font-size:24px">${Math.round(rt.total)}<span class="muted" style="font-size:12px"> nm</span></div></div>
        <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">ROUTE RISK</div><div class="nv-score" style="font-size:24px;color:${aggCol}">${rt.agg}<span class="muted" style="font-size:12px">/100</span></div></div>
        <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">CHOKEPOINTS</div><div class="nv-score" style="font-size:24px">${rt.between.length}</div></div>
        <div class="stat card" style="padding:12px 16px;flex:1;min-width:120px"><div class="muted" style="font-size:11px">REC. EMCON</div><div class="nv-score" style="font-size:20px">${esc(post.emcon)}</div></div>
      </div>
      <div class="card panel" style="padding:0;overflow-x:auto;margin-bottom:12px">
        <table class="nv-table"><thead><tr><th>From</th><th>To</th><th>Distance (nm)</th><th>Leg risk</th></tr></thead><tbody>${legRows}</tbody></table>
      </div>
      ${rt.worst ? `<div class="card panel" style="padding:14px;margin-bottom:12px">
        <div class="nv-kv"><span>Highest-risk chokepoint on route</span><b>${esc(rt.worst.c.name)} &nbsp;${badge(rt.worst.r.band, rt.worst.r.kind)} ${rt.worst.r.score}/100</b></div>
      </div>` : `<div class="nv-note" style="margin-bottom:12px">No strategic chokepoints lie on this corridor — open-water transit.</div>`}
      <div class="card panel" style="padding:14px">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px"><b>Recommended posture</b>${badge('EMCON ' + post.emcon, post.kind)}</div>
        <div class="nv-note">${esc(post.advisory)}</div>
      </div>`;
  }

  oSel.addEventListener('change', draw);
  dSel.addEventListener('change', draw);
  tSl.addEventListener('input', draw);
  jSl.addEventListener('input', draw);
  draw();
}

function panelConvoy(host) {
  const WARSHIP = ['Destroyer', 'Carrier', 'Submarine', 'Frigate', 'Cruiser'];
  const isWarship = v => WARSHIP.includes(v.cls);
  const THRESH = 60;
  const sel = new Set([0, 2, 7]); // a warship, a soft merchant, a dark ship
  const statusKind = { UNDERWAY: 'ok', MOORED: 'info', DARK: 'bad' };

  host.innerHTML = `
    <div class="pg-h2" style="font-size:15px">Convoy Planner</div>
    <div class="pg-sub" style="margin-bottom:10px">Assemble a convoy from the fleet. A convoy's cyber resilience is set by its weakest hull — one compromised bridge network can betray the group's position, route and intent. Toggle vessels to recompute.</div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px" class="nv-fleet-layout">
      <div class="card panel" style="padding:14px">
        <div class="pg-h2" style="font-size:13px;margin-bottom:8px">SELECT HULLS</div>
        <div id="nv-cv-list"></div>
      </div>
      <div class="card panel" style="padding:14px" id="nv-cv-out"></div>
    </div>`;

  const list = host.querySelector('#nv-cv-list');
  const out = host.querySelector('#nv-cv-out');

  function drawList() {
    list.innerHTML = FLEET.map((v, i) => {
      const on = sel.has(i);
      return `<label class="nv-check"><input type="checkbox" data-i="${i}"${on ? ' checked' : ''}>
        <span style="flex:1"><b style="font-size:13px">${esc(v.name)}</b><span class="muted" style="font-size:11px"> · ${esc(v.cls)} · ${v.readiness}/100</span></span>
        ${badge(v.status, statusKind[v.status])}</label>`;
    }).join('');
    list.querySelectorAll('input[type=checkbox]').forEach(cb => cb.addEventListener('change', () => {
      const i = +cb.dataset.i;
      if (cb.checked) sel.add(i); else sel.delete(i);
      drawOut();
    }));
  }

  function drawOut() {
    const ships = [...sel].sort((a, b) => a - b).map(i => FLEET[i]);
    if (!ships.length) {
      out.innerHTML = `<div class="pg-h2" style="font-size:13px;margin-bottom:8px">CONVOY STATUS</div><div class="nv-note">No hulls selected. Choose two or more vessels to form a convoy.</div>`;
      return;
    }
    const avg = Math.round(ships.reduce((a, v) => a + v.readiness, 0) / ships.length);
    const weakest = ships.slice().sort((a, b) => a.readiness - b.readiness)[0];
    const warships = ships.filter(isWarship);
    const merchants = ships.filter(v => !isWarship(v));
    const darkShips = ships.filter(v => v.status === 'DARK');
    const weakHulls = ships.filter(v => v.readiness < THRESH);
    const avgCol = avg >= 80 ? '#3ddc84' : avg >= 60 ? '#f1c40f' : '#ff6b5e';
    const minCol = weakest.readiness >= 80 ? '#3ddc84' : weakest.readiness >= 60 ? '#f1c40f' : '#ff6b5e';

    // Escort recommendation: soft merchant (low readiness or AIS-dark) needs a
    // warship screen; recommend the best-readiness warship in the selection.
    const needsEscort = merchants.some(v => v.readiness < THRESH || v.status === 'DARK');
    const bestWarship = warships.slice().sort((a, b) => b.readiness - a.readiness)[0];
    let escortHtml;
    if (needsEscort) {
      escortHtml = bestWarship
        ? `${badge('ESCORT SET', 'ok')} Assign <b>${esc(bestWarship.name)}</b> (${bestWarship.readiness}/100) to screen the low-readiness merchant traffic and provide hardened PNT/EW cover.`
        : `${badge('NO ESCORT', 'bad')} Convoy carries vulnerable merchant hulls but no warship. Add a high-readiness escort (Destroyer/Frigate) before sailing.`;
    } else if (bestWarship) {
      escortHtml = `${badge('COVERED', 'ok')} <b>${esc(bestWarship.name)}</b> provides organic escort; all merchant hulls sit above the ${THRESH}/100 readiness floor.`;
    } else {
      escortHtml = `${badge('BENIGN', 'info')} All hulls above the readiness floor; no dedicated escort required for a low-threat transit.`;
    }

    const formation = warships.length && merchants.length
      ? (warships.length >= 2
          ? 'Diamond screen — warships on the threat axes, merchants boxed in the center of the formation.'
          : 'Line-ahead with the escort leading; merchants stationed astern in the screened lane.')
      : warships.length
        ? 'Surface action group — line-abreast search-and-patrol formation.'
        : 'Merchant column — tight line-ahead to simplify station-keeping; request external escort.';

    const warnRows = [];
    darkShips.forEach(v => warnRows.push(`<div class="nv-row"><span>AIS dark — position unverifiable</span>${badge(v.name, 'bad')}</div>`));
    weakHulls.forEach(v => warnRows.push(`<div class="nv-row"><span>Below ${THRESH}/100 readiness floor</span>${badge(v.name + ' · ' + v.readiness, 'warn')}</div>`));

    out.innerHTML = `
      <div class="pg-h2" style="font-size:13px;margin-bottom:8px">CONVOY STATUS — ${ships.length} HULLS</div>
      <div class="nv-kv"><span>Composition</span><b>${warships.length} warship${warships.length !== 1 ? 's' : ''} · ${merchants.length} merchant${merchants.length !== 1 ? 's' : ''}</b></div>
      <div class="nv-kv"><span>Average readiness</span><b style="color:${avgCol}">${avg}/100</b></div>
      <div class="nv-meter"><i style="width:${avg}%;background:${avgCol}"></i></div>
      <div class="nv-kv" style="margin-top:8px"><span>Weakest link (min)</span><b style="color:${minCol}">${esc(weakest.name)} · ${weakest.readiness}/100</b></div>
      <div class="nv-meter"><i style="width:${weakest.readiness}%;background:${minCol}"></i></div>
      ${warnRows.length
        ? `<div class="pg-h2" style="font-size:12px;margin:14px 0 6px">WARNINGS</div>${warnRows.join('')}`
        : `<div class="nv-note" style="margin-top:10px">${badge('CLEAR', 'ok')} No dark ships and no hull below the ${THRESH}/100 readiness floor.</div>`}
      <div class="pg-h2" style="font-size:12px;margin:14px 0 6px">ESCORT RECOMMENDATION</div>
      <div class="nv-note">${escortHtml}</div>
      <div class="pg-h2" style="font-size:12px;margin:14px 0 6px">FORMATION</div>
      <div class="nv-note">${esc(formation)}</div>`;
  }

  drawList();
  drawOut();
}

// ---------------------------------------------------------------------------
// Main render
// ---------------------------------------------------------------------------

const TABS = [
  { id: 'fleet', label: 'FLEET COMMAND', fn: panelFleet },
  { id: 'ais', label: 'AIS INTEGRITY', fn: panelAis },
  { id: 'choke', label: 'CHOKEPOINTS', fn: panelChokepoints },
  { id: 'route', label: 'ROUTE RISK', fn: panelRoute },
  { id: 'convoy', label: 'CONVOY', fn: panelConvoy },
  { id: 'gnss', label: 'GNSS / ECDIS', fn: panelGnss },
  { id: 'cables', label: 'SUBSEA CABLES', fn: panelCables },
  { id: 'emcon', label: 'EMCON', fn: panelEmcon }
];

export function renderNavarch(main) {
  injectStyle();
  cleanupNavarch();

  main.innerHTML = `
    <div class="nv-wrap">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;flex-wrap:wrap;gap:8px">
        <div>
          <h1 class="pg-h1">NAVARCH</h1>
          <div class="pg-sub">Naval &amp; maritime cyber-defense command — fleet integrity, AIS anti-spoofing, chokepoint risk, GNSS/ECDIS assurance</div>
        </div>
        <div class="chip nv-mono" id="nv-clock" style="align-self:center"></div>
      </div>
      <div class="nv-tabs" id="nv-tabs">
        ${TABS.map((t, i) => `<button class="nv-tab${i === 0 ? ' active' : ''}" data-id="${t.id}">${esc(t.label)}</button>`).join('')}
      </div>
      <div id="nv-panel"></div>
    </div>`;

  const panel = main.querySelector('#nv-panel');
  const tabsEl = main.querySelector('#nv-tabs');

  function activate(id) {
    tabsEl.querySelectorAll('.nv-tab').forEach(b => b.classList.toggle('active', b.dataset.id === id));
    const t = TABS.find(x => x.id === id) || TABS[0];
    t.fn(panel);
  }
  tabsEl.querySelectorAll('.nv-tab').forEach(b => b.addEventListener('click', () => activate(b.dataset.id)));
  activate('fleet');

  // Live UTC clock.
  const clock = main.querySelector('#nv-clock');
  function tick() {
    if (!document.body.contains(clock)) { cleanupNavarch(); return; }
    clock.textContent = 'ZULU ' + new Date().toISOString().slice(11, 19) + 'Z';
  }
  tick();
  window._navarchTimers = window._navarchTimers || [];
  window._navarchTimers.push(setInterval(tick, 1000));
}

export function cleanupNavarch() {
  if (Array.isArray(window._navarchTimers)) {
    window._navarchTimers.forEach(t => clearInterval(t));
  }
  window._navarchTimers = [];
}
