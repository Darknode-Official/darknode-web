// From-scratch game synthesis — a primitive grammar, not a parts catalogue.
//
// The shipped gamegen.js composes a game by choosing ONE of four authored genre
// bodies (shooter / dodger / catcher / runner) and filling parameters. This file
// takes the harder road the user asked for: there are NO genre bodies here. A
// request is parsed into an intermediate representation (IR) built from ATOMIC
// primitives — entities, motion behaviours, collision rules, controls, goals —
// and a code emitter walks that IR to EMIT a complete canvas program line by
// line. The primitives combine freely, so requests that no fixed genre could
// express ("squares that fall AND bounce while you shoot homing balls at them")
// synthesize into real, novel programs. Still deterministic (a seed keyed off
// the words fixes every free choice) and still no model / no network.
//
// IR = {
//   meta:   { title, W, H, palette:{bg,fg,accent} },
//   player: { shape, color, size, control, shoots, projectile },
//   actors: [ { id, shape, color, size, origin, rate, speed, motions:[],
//               onPlayer, onProjectile, offscreen, points } ],
//   goal:   { lives, winScore, surviveSec },
// }
//   control ∈ horizontal | omni | jumper
//   motion  ∈ fall rise driftWrap driftBounce sine homeX chase scrollLeft gravity
//   onPlayer∈ lose end bounce catch none      offscreen ∈ recycle remove score lose

// --- deterministic seed: the same sentence always yields the same program ----
function hashStr(s) {
  let h = 2166136261 >>> 0;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function rng32(seed) {
  let a = seed >>> 0;
  return function () {
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const pick = (rnd, arr) => arr[Math.floor(rnd() * arr.length)];

// --- vocabulary ---------------------------------------------------------------
const COLORS = {
  red: "#ff4d4d", crimson: "#ff2d55", green: "#5aff7a", lime: "#b6ff00", blue: "#4db5ff",
  cyan: "#4df3ff", teal: "#2fd4c4", yellow: "#ffe14d", gold: "#ffd34d", orange: "#ff9d4d",
  purple: "#b45cff", violet: "#9b5cff", pink: "#ff7ad1", magenta: "#ff2bd6", white: "#ffffff",
  black: "#101016", gray: "#9aa0b4", grey: "#9aa0b4", silver: "#d0d4e0",
};
const COLOR_RE = new RegExp("\\b(" + Object.keys(COLORS).join("|") + ")\\b");
const SHAPES = ["circle", "square", "triangle", "diamond", "star", "bar"];
const SHAPE_WORD = {
  circle: "circle", circles: "circle", ball: "circle", balls: "circle", round: "circle", sphere: "circle", orb: "circle", dot: "circle", bubble: "circle",
  square: "square", squares: "square", block: "square", blocks: "square", box: "square", cube: "square", brick: "square",
  triangle: "triangle", triangles: "triangle", ship: "triangle", arrow: "triangle", wedge: "triangle",
  diamond: "diamond", diamonds: "diamond", gem: "diamond", crystal: "diamond", kite: "diamond",
  star: "star", stars: "star", sparkle: "star",
  bar: "bar", laser: "bar", beam: "bar", line: "bar", rod: "bar", dash: "bar",
};
const SHAPE_NOUN_RE = new RegExp("\\b(" + Object.keys(SHAPE_WORD).join("|") + ")\\b");

function colorNear(low, nounRe) {
  const before = low.match(new RegExp(COLOR_RE.source + "(?:[\\s-]+\\w+){0,2}[\\s-]+" + nounRe.source));
  if (before) return COLORS[before[1]];
  const after = low.match(new RegExp(nounRe.source + "\\s+(?:is|are|in|as|should be|coloured|colored)\\s+(?:a\\s+)?" + COLOR_RE.source));
  if (after) return COLORS[after[after.length - 1]];
  return null;
}
// Token-window binding: find a shape word within `win` tokens of any anchor word.
// A shape word is only claimed once (via `used`) so "shoot balls at squares" gives
// the projectile the ball and the actor the square, not both the same shape.
function shapeForRole(toks, anchors, win, used) {
  for (let i = 0; i < toks.length; i++) {
    if (!anchors.has(toks[i])) continue;
    for (let d = 0; d <= win; d++) {
      for (const j of [i - d, i + d]) {
        if (j < 0 || j >= toks.length || used.has(j)) continue;
        if (SHAPE_WORD[toks[j]] && !anchors.has(toks[j])) { used.add(j); return SHAPE_WORD[toks[j]]; }
      }
    }
  }
  return null;
}
// Any remaining unclaimed shape word (e.g. "dodge the triangles") -> the actor.
function looseShape(toks, used) {
  for (let i = 0; i < toks.length; i++) if (!used.has(i) && SHAPE_WORD[toks[i]]) { used.add(i); return SHAPE_WORD[toks[i]]; }
  return null;
}

// --------------------------------------------------------------------------
// PARSE: a request -> an IR (or null when it is not a game-build request).
// --------------------------------------------------------------------------
const GAME_WORD = /\b(game|arcade|mini[- ]?game|play|playable)\b/;
const UNSUPPORTED = /\b(chess|checkers|draughts|poker|blackjack|solitaire|sudoku|minesweeper|tetris|2048|mario|pac[- ]?man|battleship|mahjong|scrabble|monopoly|rubik|crossword|wordle|rpg|mmo|fps|racing|racer)\b/;

export function buildIR(request) {
  const low = " " + String(request || "").toLowerCase().trim() + " ";
  if (UNSUPPORTED.test(low)) return null;        // a named ruleset our primitives don't cover — declined honestly

  // --- intent flags read straight from the words (independent, combinable) ---
  const wantsShoot = /\b(shoot\w*|gun|blast\w*|fire\w*|laser\w*|bullet\w*|shmup)\b/.test(low);
  const wantsJump = /\b(jump\w*|runner|running|endless runner|flappy|dino|hop|hopper|platformer)\b/.test(low);
  const wantsCatch = /\b(catch\w*|collect\w*|basket|harvest\w*|gather\w*|grab\w*)\b/.test(low);
  const wantsDodge = /\b(dodg\w*|avoid\w*|surviv\w*|asteroid\w*|meteor\w*|rain|falling)\b/.test(low);
  const wantsBounce = /\b(bounc\w*|bouncy|ricochet\w*|rebound\w*)\b/.test(low);
  const wantsWave = /\b(zigzag|zig-zag|wave|wavy|weav\w*|sine|sway\w*|wobbl\w*|wiggl\w*)\b/.test(low);
  const wantsChase = /\b(homing|home in|chas\w*|follow\w*|seek\w*|track\w*|hunt\w*)\b/.test(low);
  const wantsSwarm = /\b(swarm|horde|many|lots|tons|hundreds|wave of|army|flood)\b/.test(low);
  const hard = /\b(hard|insane|fast|brutal|intense|difficult)\b/.test(low);
  const easy = /\b(easy|slow|chill|relaxed|simple|calm)\b/.test(low);

  const anyIntent = wantsShoot || wantsJump || wantsCatch || wantsDodge;
  if (!GAME_WORD.test(low) && !anyIntent && !SHAPE_NOUN_RE.test(low)) return null;

  const rnd = rng32(hashStr(low));
  const toks = low.split(/[^a-z0-9]+/).filter(Boolean);
  const usedShapes = new Set();   // token indices already claimed as a shape, so each is used once

  // --- palette (from colour words or seed) -----------------------------------
  const bgWord = colorNear(low, /(?:background|backdrop|sky|screen|field|arena)/);
  const palette = {
    bg: bgWord || pick(rnd, ["#05050c", "#0d0221", "#0a1008", "#0a1830", "#08080a"]),
    fg: "#eef3ff",
    accent: pick(rnd, ["#30304a", "#3a1f5d", "#1f3a1a", "#1d3350", "#2a2a30"]),
  };

  // --- player: control scheme comes from intent, shape/colour from words -----
  // Shapes are bound to roles in priority order (player, then projectile, then
  // actor) so each named shape is claimed once by the thing it describes.
  const PLAYER_ANCHORS = new Set(["player", "ship", "hero", "paddle", "basket", "cannon", "turret", "me", "my", "character", "guy", "you"]);
  const PROJ_ANCHORS = new Set(["bullet", "bullets", "projectile", "projectiles", "shot", "shots", "ammo", "laser", "lasers", "missile", "missiles", "shoot", "shoots", "shooting", "fire", "fires", "firing"]);
  const ACTOR_ANCHORS = new Set(["enemy", "enemies", "foe", "foes", "alien", "aliens", "monster", "monsters", "zombie", "zombies", "target", "targets", "invader", "invaders", "asteroid", "asteroids", "rock", "rocks", "obstacle", "obstacles", "pipe", "pipes", "gem", "gems", "fruit", "coin", "coins", "dodge", "avoid", "catch", "collect", "falling", "them", "things"]);

  const control = wantsJump ? "jumper" : (/\b(up and down|up\/down|vertical|omni|free move|free movement|8-?way|any direction|all directions)\b/.test(low)) ? "omni" : "horizontal";
  const playerShape = shapeForRole(toks, PLAYER_ANCHORS, 3, usedShapes);
  const projShape = wantsShoot ? shapeForRole(toks, PROJ_ANCHORS, 3, usedShapes) : null;
  const player = {
    shape: playerShape || (wantsShoot ? "triangle" : wantsCatch ? "bar" : control === "jumper" ? "square" : "bar"),
    color: colorNear(low, /(?:player|ship|hero|paddle|basket|cannon|turret|me|my ship)/) || "#4df3ff",
    size: 20,
    control,
    shoots: wantsShoot,
    projectile: null,
  };
  if (wantsShoot) {
    const homing = /\b(homing|home[- ]?in|seeking?)\b/.test(low) || (wantsChase && /\b(bullet\w*|shot\w*|projectile\w*|missile\w*|ball\w*|laser\w*)\b/.test(low) && !/\b(enem\w*|alien\w*|monster\w*|foe\w*|target\w*)\b/.test(low));
    player.projectile = {
      shape: projShape || "bar",
      color: colorNear(low, /(?:bullet|bullets|projectile|laser|shot|ammo|ball|orb)/) || "#ffe14d",
      size: /\b(huge|big|large|giant|massive)\b/.test(low) ? 8 : /\b(tiny|small|thin|mini)\b/.test(low) ? 3 : 5,
      speed: 9,
      homing,
    };
  }

  // --- actors: one or more spawned entity streams ----------------------------
  // The default "threat" actor; its rules are decided by the verbs present.
  const baseSpeed = +(1.2 + rnd() * 0.7 + (hard ? 0.9 : 0) - (easy ? 0.4 : 0)).toFixed(2);
  const rate = Math.max(16, Math.round(72 - rnd() * 16 - (hard ? 22 : 0) + (easy ? 18 : 0) - (wantsSwarm ? 26 : 0)));
  const actorShape = shapeForRole(toks, ACTOR_ANCHORS, 3, usedShapes) || looseShape(toks, usedShapes);
  const threat = {
    id: "a0",
    shape: actorShape || pick(rnd, ["circle", "square", "diamond"]),
    color: colorNear(low, /(?:enemy|enemies|foe|foes|alien|aliens|monster|monsters|zombie|zombies|target|targets|asteroid|obstacle|gem|gems|fruit|coin)/) || (wantsCatch ? "#ffd34d" : "#ff5c7a"),
    size: wantsSwarm ? 12 : 15,
    origin: control === "jumper" ? "left" : "top",
    rate,
    speed: baseSpeed,
    motions: [],
    onPlayer: wantsCatch ? "catch" : wantsShoot && !wantsDodge ? "lose" : control === "jumper" ? "end" : "lose",
    onProjectile: wantsShoot ? "destroy" : "none",
    offscreen: wantsCatch ? "lose" : control === "jumper" ? "remove" : wantsShoot ? "remove" : "score",
    points: 10,
  };
  // compose motion atoms — several can stack
  if (control === "jumper") threat.motions.push("scrollLeft");
  else threat.motions.push("fall");
  if (wantsBounce) threat.motions.push("driftBounce");
  if (wantsWave) threat.motions.push("sine");
  if (wantsChase && !player.projectile?.homing) threat.motions.push(control === "jumper" ? "homeX" : "chase");
  if (/\b(accelerat|speed up|gravity|heavy)\b/.test(low) && control !== "jumper") threat.motions.push("gravity");

  const actors = [threat];

  // --- goal ------------------------------------------------------------------
  const goal = {
    lives: control === "jumper" ? 1 : easy ? 5 : hard ? 2 : 3,
    winScore: /\bwin (?:at|on|after)? ?(\d{2,4})\b/.test(low) ? +RegExp.$1 : 0,
    surviveSec: /\bsurvive (?:for )?(\d{1,3}) ?(?:s|sec|second)/.test(low) ? +RegExp.$1 : 0,
  };

  // --- honesty: name described mechanics this grammar genuinely cannot build --
  // Rather than silently forcing these into the arcade mould, we surface them so
  // the UI can say plainly what was and was not synthesized.
  const CANT = [
    [/\b(maze|labyrinth)\b/, "a maze / walls to navigate"],
    [/\b(grow|growing|plant|water|farm|crops?)\b/, "growth / tending mechanics"],
    [/\b(typ(e|ing)|spell\w*|word\s+game|guess\w*|wordle)\b/, "typing / word mechanics"],
    [/\b(puzzle|match[- ]?3|tile\w*|memory game|pair\w*)\b/, "puzzle / matching mechanics"],
    [/\b(turn[- ]?based|inventory|level up|levelling|rpg|quest|story|dialog\w*)\b/, "RPG / progression mechanics"],
    [/\b(multiplayer|two player|2 ?player|versus|co-?op|online)\b/, "multiplayer"],
    [/\b(physics|rope|fluid|cloth|ragdoll|orbit\w*|gravity well)\b/, "advanced physics"],
    [/\b(3d|three[- ]?dimensional|first[- ]?person|voxel|raycast\w*)\b/, "3D rendering"],
    [/\b(card\w*|deck|dice|board game|hex grid)\b/, "card / board mechanics"],
    [/\b(paint|draw\w*|music|rhythm|sound\w*|audio)\b/, "drawing / audio mechanics"],
  ];
  const caveats = [];
  for (const [re, label] of CANT) if (re.test(low)) caveats.push(label);

  // --- title -----------------------------------------------------------------
  const verb = wantsShoot ? "Shooter" : wantsCatch ? "Catcher" : wantsJump ? "Runner" : wantsDodge ? "Dodger" : "Arcade";
  const adj = wantsChase ? "Homing " : wantsBounce ? "Bouncing " : wantsWave ? "Weaving " : wantsSwarm ? "Swarm " : "";
  const field = control === "jumper" ? { W: 640, H: 360 } : { W: 440, H: 640 };

  return {
    meta: { title: (adj + verb).trim(), W: field.W, H: field.H, palette },
    player, actors, goal, caveats,
    describe: describeIR({ player, actors, goal, wantsShoot, wantsCatch, wantsJump, wantsDodge, wantsBounce, wantsWave, wantsChase }),
  };
}

// A plain-English readback of what was composed — proof it understood the words.
function describeIR(x) {
  const bits = [];
  bits.push("you control a " + x.player.shape + (x.player.control === "jumper" ? " that jumps (gravity + ground)" : x.player.control === "omni" ? " moving freely" : " moving left/right"));
  if (x.player.shoots) bits.push("firing " + (x.player.projectile.homing ? "homing " : "") + x.player.projectile.shape + " projectiles");
  const a = x.actors[0];
  const motion = a.motions.map((m) => ({ fall: "fall", rise: "rise", scrollLeft: "scroll in", driftBounce: "bounce off walls", sine: "weave side to side", homeX: "track you horizontally", chase: "chase you", gravity: "accelerate" }[m] || m)).join(" + ");
  bits.push(a.shape + "s that " + motion + (a.onPlayer === "catch" ? ", which you catch for points" : a.onPlayer === "lose" || a.onPlayer === "end" ? ", which cost you on contact" : ""));
  return bits.join("; ") + ".";
}

// --------------------------------------------------------------------------
// EMIT: an IR -> a complete, self-contained HTML/canvas program.
// --------------------------------------------------------------------------
function shapeDraw(shape, varName, sizeExpr) {
  // returns a code fragment that fills `shape` at (<v>.x,<v>.y) with current fillStyle
  const v = varName, r = sizeExpr;
  switch (shape) {
    case "circle": return "ctx.beginPath(); ctx.arc(" + v + ".x, " + v + ".y, " + r + ", 0, Math.PI*2); ctx.fill();";
    case "square": return "ctx.fillRect(" + v + ".x-" + r + ", " + v + ".y-" + r + ", " + r + "*2, " + r + "*2);";
    case "triangle": return "ctx.beginPath(); ctx.moveTo(" + v + ".x, " + v + ".y-" + r + "); ctx.lineTo(" + v + ".x-" + r + ", " + v + ".y+" + r + "); ctx.lineTo(" + v + ".x+" + r + ", " + v + ".y+" + r + "); ctx.closePath(); ctx.fill();";
    case "diamond": return "ctx.beginPath(); ctx.moveTo(" + v + ".x, " + v + ".y-" + r + "); ctx.lineTo(" + v + ".x+" + r + ", " + v + ".y); ctx.lineTo(" + v + ".x, " + v + ".y+" + r + "); ctx.lineTo(" + v + ".x-" + r + ", " + v + ".y); ctx.closePath(); ctx.fill();";
    case "star": return "star(ctx, " + v + ".x, " + v + ".y, " + r + ");";
    case "bar": default: return "ctx.fillRect(" + v + ".x-" + r + ", " + v + ".y-" + r + "*0.5, " + r + "*2, " + r + ");";
  }
}
// per-actor motion atom -> a line inside the entity loop (e is the entity)
function motionLine(atom) {
  switch (atom) {
    case "fall": return "e.y += e.vy;";
    case "rise": return "e.y -= e.vy;";
    case "scrollLeft": return "e.x -= e.vy;";
    case "driftBounce": return "e.x += e.vx; if (e.x < e.r || e.x > W - e.r) { e.vx = -e.vx; e.x = Math.max(e.r, Math.min(W - e.r, e.x)); }";
    case "sine": return "e.x = e.bx + Math.sin((t + e.ph) / 26) * 60;";
    case "homeX": return "e.x += Math.sign(player.x - e.x) * 1.4;";
    case "chase": return "e.x += Math.sign(player.x - e.x) * 1.1; e.y += Math.sign(player.y - e.y) * 0.5;";
    case "gravity": return "e.vy += 0.06;";
    default: return "";
  }
}

export function emit(ir) {
  const p = ir.player, a = ir.actors[0], g = ir.goal, P = ir.meta.palette;
  const jumper = p.control === "jumper";
  const L = []; // lines of the <script> body

  L.push('const canvas = document.getElementById("game");');
  L.push('const ctx = canvas.getContext("2d");');
  L.push("const W = canvas.width, H = canvas.height;");
  if (jumper) L.push("const GROUND = H - 34;");
  L.push("const keys = {}; let t = 0;");
  L.push("let player, actors, bullets, score, best = 0, lives, over, spawnTimer, cooldown;");
  L.push("function star(c,x,y,r){ c.beginPath(); for(let i=0;i<10;i++){ const a=Math.PI/5*i-Math.PI/2, rr=i%2?r*0.45:r; c[i?'lineTo':'moveTo'](x+Math.cos(a)*rr, y+Math.sin(a)*rr);} c.closePath(); c.fill(); }");

  // reset()
  L.push("function reset() {");
  if (jumper) L.push("  player = { x: 90, y: GROUND, vy: 0, r: " + p.size + ", onGround: true };");
  else L.push("  player = { x: W/2, y: H - 46, r: " + p.size + " };");
  L.push("  actors = []; bullets = []; cooldown = 0;");
  L.push("  score = 0; lives = " + g.lives + "; over = false; spawnTimer = 0;");
  L.push("}");

  // spawn()
  L.push("function spawn() {");
  if (a.origin === "left") L.push("  const e = { x: W + 20, y: GROUND - (Math.random()<0.5?0:40), r: " + a.size + ", vy: " + a.speed + " + score/600, vx: 0, bx: 0, ph: 0, dead: false };");
  else L.push("  const e = { x: 24 + Math.random()*(W-48), y: -20, r: " + a.size + ", vy: " + a.speed + " + Math.random()*1.1 + score/600, vx: (Math.random()<0.5?-1:1)*(1+Math.random()*1.5), bx: 0, ph: Math.random()*100, dead: false }; e.bx = e.x;");
  L.push("  actors.push(e);");
  L.push("}");

  if (p.shoots) {
    L.push("function fire() { if (over || cooldown > 0) return; bullets.push({ x: player.x, y: player.y - player.r, tx: 0 }); cooldown = 9; }");
  }
  L.push("function loseLife() { lives--; if (lives <= 0) endGame(); }");
  L.push("function endGame() { over = true; best = Math.max(best, score); }");

  // update()
  L.push("function update() {");
  L.push("  t++; if (over) return;");
  if (jumper) {
    L.push("  if ((keys[' '] || keys.ArrowUp || keys.w) && player.onGround) { player.vy = -11; player.onGround = false; }");
    L.push("  player.vy += 0.6; player.y += player.vy; if (player.y >= GROUND) { player.y = GROUND; player.vy = 0; player.onGround = true; }");
  } else {
    L.push("  if (keys.ArrowLeft || keys.a) player.x -= 6;");
    L.push("  if (keys.ArrowRight || keys.d) player.x += 6;");
    L.push("  player.x = Math.max(player.r, Math.min(W - player.r, player.x));");
    if (p.control === "omni") {
      L.push("  if (keys.ArrowUp || keys.w) player.y -= 6;");
      L.push("  if (keys.ArrowDown || keys.s) player.y += 6;");
      L.push("  player.y = Math.max(player.r, Math.min(H - player.r, player.y));");
    }
  }
  if (p.shoots) {
    L.push("  if (cooldown > 0) cooldown--;");
    if (p.projectile.homing) {
      L.push("  for (const b of bullets) { let best=null,bd=1e9; for (const e of actors) { const d=(e.x-b.x)**2+(e.y-b.y)**2; if(d<bd){bd=d;best=e;} } if (best) b.tx = Math.sign(best.x-b.x)*3; b.x += b.tx; b.y -= " + p.projectile.speed + "; }");
    } else {
      L.push("  for (const b of bullets) b.y -= " + p.projectile.speed + ";");
    }
    L.push("  bullets = bullets.filter(b => b.y > -20);");
  }
  L.push("  if (--spawnTimer <= 0) { spawn(); spawnTimer = Math.max(12, " + a.rate + " - score/30); }");
  L.push("  for (const e of actors) {");
  for (const m of a.motions) { const line = motionLine(m); if (line) L.push("    " + line); }
  L.push("  }");
  // projectile vs actor
  if (p.shoots && a.onProjectile === "destroy") {
    L.push("  for (const e of actors) for (const b of bullets) if (Math.abs(b.x-e.x) < e.r+4 && Math.abs(b.y-e.y) < e.r+4) { e.dead = true; b.y = -999; score += " + a.points + "; }");
  }
  // player vs actor
  L.push("  for (const e of actors) {");
  L.push("    const hit = Math.abs(e.x-player.x) < e.r+player.r && Math.abs(e.y-player.y) < e.r+player.r;");
  if (a.onPlayer === "catch") L.push("    if (hit) { e.dead = true; score += " + a.points + "; }");
  else if (a.onPlayer === "end") L.push("    if (hit) { e.dead = true; endGame(); }");
  else if (a.onPlayer === "bounce") L.push("    if (hit) { e.vy = -Math.abs(e.vy); score += 1; }");
  else if (a.onPlayer === "lose") L.push("    if (hit) { e.dead = true; loseLife(); }");
  // offscreen handling
  const off = jumper ? "e.x < -e.r" : "e.y > H + e.r";
  if (a.offscreen === "score") L.push("    else if (" + off + ") { e.dead = true; score += 5; }");
  else if (a.offscreen === "lose") L.push("    else if (" + off + ") { e.dead = true; loseLife(); }");
  else L.push("    else if (" + off + ") { e.dead = true; }");
  L.push("  }");
  L.push("  actors = actors.filter(e => !e.dead);");
  if (g.winScore) L.push("  if (score >= " + g.winScore + ") endGame();");
  if (g.surviveSec) L.push("  if (t >= " + (g.surviveSec * 60) + ") endGame();");
  L.push("}");

  // draw()
  L.push("function draw() {");
  L.push('  ctx.fillStyle = "' + P.bg + '"; ctx.fillRect(0, 0, W, H);');
  if (jumper) L.push('  ctx.fillStyle = "' + P.accent + '"; ctx.fillRect(0, GROUND + player.r, W, H);');
  L.push('  ctx.fillStyle = "' + p.color + '"; ' + shapeDraw(p.shape, "player", "player.r"));
  if (p.shoots) L.push('  ctx.fillStyle = "' + p.projectile.color + '"; for (const b of bullets) { ' + shapeDraw(p.projectile.shape, "b", String(p.projectile.size)) + " }");
  L.push('  ctx.fillStyle = "' + a.color + '"; for (const e of actors) { ' + shapeDraw(a.shape, "e", "e.r") + " }");
  L.push('  ctx.fillStyle = "' + P.fg + '"; ctx.font = "16px monospace"; ctx.textAlign = "left"; ctx.fillText("Score " + score, 10, 22);');
  L.push('  ctx.textAlign = "right"; ctx.fillText(' + (jumper ? '"Best " + best' : '"Lives " + lives') + ", W - 10, 22);");
  L.push("  if (over) {");
  L.push('    ctx.textAlign = "center"; ctx.fillStyle = "' + P.fg + '";');
  L.push('    ctx.font = "34px monospace"; ctx.fillText(' + (g.winScore ? "score >= " + g.winScore + ' ? "YOU WIN" : "GAME OVER"' : '"GAME OVER"') + ", W/2, H/2 - 12);");
  L.push('    ctx.font = "15px monospace"; ctx.fillText("Score " + score + "   Best " + best, W/2, H/2 + 14);');
  L.push('    ctx.fillText("Press Space / click to play again", W/2, H/2 + 40);');
  L.push("  }");
  L.push("}");

  // input + loop
  L.push('document.addEventListener("keydown", e => { keys[e.key] = true;');
  L.push('  if (e.key === " ") { if (over) reset(); ' + (p.shoots ? "else fire();" : "") + " }");
  L.push('  if (["ArrowLeft","ArrowRight","ArrowUp","ArrowDown"," "].includes(e.key)) e.preventDefault();');
  L.push("});");
  L.push('document.addEventListener("keyup", e => { keys[e.key] = false; });');
  if (!jumper) L.push('canvas.addEventListener("mousemove", e => { const r = canvas.getBoundingClientRect(); player.x = (e.clientX - r.left) * (W / r.width); });');
  L.push('canvas.addEventListener("mousedown", () => { if (over) reset(); ' + (p.shoots ? "else fire();" : jumper ? 'else { if (player.onGround) { player.vy = -11; player.onGround = false; } }' : "") + " });");
  L.push("function loop() { update(); draw(); requestAnimationFrame(loop); }");
  L.push("reset(); loop();");

  const script = L.join("\n");
  const instr = jumper ? "Space / Up / click to jump. One life — go as far as you can."
    : p.shoots ? "Arrow keys / A D / mouse to move. Space / click to shoot."
      : a.onPlayer === "catch" ? "Arrow keys / A D / mouse to move. Catch them, do not drop them."
        : "Arrow keys / A D / mouse to move. " + (p.control === "omni" ? "Up/Down too. " : "") + "Avoid them.";

  return [
    "<!DOCTYPE html>", '<html lang="en"><head><meta charset="UTF-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1.0">',
    "<title>" + ir.meta.title + "</title><style>",
    "body{margin:0;background:" + P.bg + ";display:flex;flex-direction:column;align-items:center;justify-content:center;min-height:100vh;color:" + P.fg + ";font-family:system-ui,sans-serif}",
    "canvas{border:2px solid " + P.accent + ";max-width:95vw;background:" + P.bg + ";touch-action:none}",
    "p{opacity:.7;font-size:13px;margin:10px 16px;text-align:center}",
    "</style></head><body>",
    '<canvas id="game" width="' + ir.meta.W + '" height="' + ir.meta.H + '"></canvas>',
    "<p>" + instr + "</p><script>", script, "</" + "script></body></html>",
  ].join("\n");
}

// A request -> { title, code, ir, lead, note } or null.
export function synthFromScratch(request) {
  const ir = buildIR(request);
  if (!ir) return null;
  const code = emit(ir);
  const lead = "A complete, playable **" + ir.meta.title + "** built from scratch. There is no genre template behind this — DI parsed your words into an entity/behaviour/rule graph and emitted the program line by line from atomic primitives. What it composed: " + ir.describe;
  const caveat = ir.caveats.length
    ? "Being honest: this is a deterministic, no-AI grammar, so it can't build " + ir.caveats.join(", ") + ". I built the closest arcade game from the parts I understood — if you need those mechanics exactly, that needs the AI path, not this offline one."
    : "";
  const note = "Synthesized by DI's from-scratch grammar (gamegen-scratch.js): the IR is assembled from independent primitives (entities × motions × rules × controls), so the same words always build the same program and different words build a structurally different one. No model, no network.";
  return { title: ir.meta.title, code, ir, lead, caveat, note };
}
