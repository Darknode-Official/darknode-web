// Copyright (c) 2026 Darknode-Official (Manav Prasad). All rights reserved.
//
// Pure, dependency-free layout math for the Security Graph node-link view.
// Kept free of any DOM/localStorage import so it runs under plain Node for
// unit tests (`node test/run.mjs`). The browser UI (security-graph-ui.js)
// imports these helpers and does all the rendering/interaction.

// Deterministic PRNG (mulberry32): same seed -> same stream, so a given
// (nodes, edges, seed) always yields identical positions.
export function mulberry32(seed) {
  let a = (seed >>> 0) || 1;
  return function () {
    a |= 0; a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function nodeId(n) { return typeof n === 'string' ? n : (n && n.id); }

// Normalize an edge list to [fromId, toId] pairs, tolerant of several shapes
// ({fromId,toId} relationships, {source,target}, {from,to}).
export function normalizeEdges(edges, has) {
  const out = [];
  for (const e of edges || []) {
    if (!e) continue;
    const a = e.fromId ?? e.source ?? e.from;
    const b = e.toId ?? e.target ?? e.to;
    if (a == null || b == null || a === b) continue;
    if (has && (!has(a) || !has(b))) continue;
    out.push([a, b]);
  }
  return out;
}

// Fruchterman-Reingold force-directed layout.
// Returns { [id]: {x, y} }. Deterministic for a given seed. Positions are
// clamped inside [margin, width-margin] x [margin, height-margin], so the
// output never contains NaN/Infinity and always sits within bounds.
export function layout(nodes, edges, opts = {}) {
  const width = opts.width || 1000;
  const height = opts.height || 700;
  const margin = opts.margin || 30;
  const iterations = opts.iterations || 300;
  const seed = opts.seed == null ? 1 : opts.seed;

  const ids = (nodes || []).map(nodeId).filter((id) => id != null);
  const n = ids.length;
  const out = {};
  if (n === 0) return out;

  const rand = mulberry32(seed);
  const pos = {};
  // Pre-placed/pinned positions (e.g. a node the user dragged) are honored.
  const pinned = opts.pinned || {};
  const minX = margin, maxX = width - margin, minY = margin, maxY = height - margin;
  for (const id of ids) {
    const p = pinned[id];
    if (p && isFinite(p.x) && isFinite(p.y)) {
      pos[id] = { x: Math.max(minX, Math.min(maxX, p.x)), y: Math.max(minY, Math.min(maxY, p.y)), fixed: true };
    } else {
      pos[id] = { x: minX + rand() * (maxX - minX), y: minY + rand() * (maxY - minY), fixed: false };
    }
  }

  if (n === 1) { return { [ids[0]]: { x: pos[ids[0]].x, y: pos[ids[0]].y } }; }

  const idSet = new Set(ids);
  const E = normalizeEdges(edges, (id) => idSet.has(id));

  const area = width * height;
  const k = Math.sqrt(area / n); // ideal edge length
  let temp = Math.max(width, height) * 0.1;
  const cool = temp / (iterations + 1);
  // Mild gravity toward the centre. Without it, repulsion in a small graph
  // pushes every node to the walls and leaves the middle empty; this pulls the
  // cluster back in while staying deterministic and bounded.
  const grav = opts.gravity == null ? 0.045 : opts.gravity;
  const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;

  const disp = {};
  for (let iter = 0; iter < iterations; iter++) {
    for (const id of ids) { disp[id] = { x: 0, y: 0 }; }

    // Repulsion between every pair.
    for (let i = 0; i < n; i++) {
      for (let j = i + 1; j < n; j++) {
        const a = ids[i], b = ids[j];
        let dx = pos[a].x - pos[b].x;
        let dy = pos[a].y - pos[b].y;
        let dist = Math.sqrt(dx * dx + dy * dy);
        if (dist < 0.01) { dx = (rand() - 0.5) * 0.1 || 0.05; dy = (rand() - 0.5) * 0.1 || 0.05; dist = Math.sqrt(dx * dx + dy * dy) || 0.01; }
        const rep = (k * k) / dist;
        const ux = dx / dist, uy = dy / dist;
        disp[a].x += ux * rep; disp[a].y += uy * rep;
        disp[b].x -= ux * rep; disp[b].y -= uy * rep;
      }
    }

    // Attraction along edges.
    for (const [a, b] of E) {
      let dx = pos[a].x - pos[b].x;
      let dy = pos[a].y - pos[b].y;
      let dist = Math.sqrt(dx * dx + dy * dy) || 0.01;
      const att = (dist * dist) / k;
      const ux = dx / dist, uy = dy / dist;
      disp[a].x -= ux * att; disp[a].y -= uy * att;
      disp[b].x += ux * att; disp[b].y += uy * att;
    }

    // Gravity: pull every free node gently toward the centre.
    for (const id of ids) {
      if (pos[id].fixed) continue;
      disp[id].x += (cx - pos[id].x) * grav * k * 0.05;
      disp[id].y += (cy - pos[id].y) * grav * k * 0.05;
    }

    // Apply, bounded by the current temperature, then clamp to bounds.
    for (const id of ids) {
      if (pos[id].fixed) continue;
      const d = disp[id];
      const dl = Math.sqrt(d.x * d.x + d.y * d.y) || 0.01;
      const lim = Math.min(dl, temp);
      let nx = pos[id].x + (d.x / dl) * lim;
      let ny = pos[id].y + (d.y / dl) * lim;
      if (!isFinite(nx)) nx = pos[id].x;
      if (!isFinite(ny)) ny = pos[id].y;
      pos[id].x = Math.max(minX, Math.min(maxX, nx));
      pos[id].y = Math.max(minY, Math.min(maxY, ny));
    }
    temp = Math.max(temp - cool, 0.01);
  }

  for (const id of ids) out[id] = { x: pos[id].x, y: pos[id].y };
  return out;
}

// Euclidean distance between two {x,y} points.
export function dist(a, b) {
  const dx = a.x - b.x, dy = a.y - b.y;
  return Math.sqrt(dx * dx + dy * dy);
}

// Normalize an export payload (from exportAll(): {entities,relationships,...})
// OR a bare array into a clean list of importable entity items, dropping
// anything without a usable type. Round-trips an exportAll().entities array.
export function normalizeImport(parsed) {
  if (!parsed) return [];
  const items = Array.isArray(parsed) ? parsed : (Array.isArray(parsed.entities) ? parsed.entities : []);
  return items.filter((it) => it && typeof it === 'object' && typeof it.type === 'string' && it.type);
}
