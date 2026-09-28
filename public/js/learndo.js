// Learn & Do — the hub that turns the whole platform into a guided set of things to do.
// Pure catalog + filter/progress logic live in learndo-data.js (unit-tested); this file is the
// thin DOM layer. It reuses the AWS-console page classes (pg-h1/pg-sub/pg-h2/cs-filter/chip/
// arse-grid/arse-card/an/ad/au) so it looks native, and navigates via the existing data-sec
// mechanism (window.dnNavigate, with a sidebar-click fallback).
import { ACTIVITIES, CATEGORIES, LEVELS, filterActivities, progressStats, validActivities } from "/js/learndo-data.js";

const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const DONE_KEY = "sw_do_done";
const LEARN_KEY = "sw_learn_progress";

// category color name -> hex dot (cosmetic only)
const HUE = {
  emerald: "#3fb950", red: "#f85149", cyan: "#39c5cf", green: "#3fb950", orange: "#d29922",
  purple: "#bc4dff", indigo: "#6e7bff", teal: "#2dd4bf", yellow: "#e3b341", violet: "#a371f7",
};

function loadDone() {
  try { const a = JSON.parse(localStorage.getItem(DONE_KEY)); return Array.isArray(a) ? a.filter(Boolean) : []; }
  catch (_) { return []; }
}
function saveDone(ids) { try { localStorage.setItem(DONE_KEY, JSON.stringify(ids)); } catch (_) {} }
function loadLearn() {
  try { const d = JSON.parse(localStorage.getItem(LEARN_KEY)) || {}; return { xp: d.xp || 0, streak: d.streak || 0, topics: (d.completedTopics || []).length }; }
  catch (_) { return { xp: 0, streak: 0, topics: 0 }; }
}
const RANKS = [[0, "Noob"], [500, "Script Kiddie"], [2000, "Hacker"], [5000, "Elite"], [10000, "L33t"], [20000, "Shadow"], [40000, "Ghost"]];
function rankOf(xp) { let r = RANKS[0][1]; for (const [t, n] of RANKS) if (xp >= t) r = n; return r; }

function navTo(sec) {
  if (!sec) return;
  if (typeof window.dnNavigate === "function" && window.dnNavigate(sec)) return;
  const it = document.querySelector('.side-item[data-sec="' + sec + '"]');
  if (it) it.click();
}

export function renderLearnDo(main) {
  const knownSecs = Array.isArray(window.dnSections) ? new Set(window.dnSections.map((s) => s.sec)) : null;
  const acts = validActivities(ACTIVITIES, knownSecs);
  const cats = CATEGORIES.filter((c) => acts.some((a) => a.cat === c.id));
  let doneIds = loadDone();

  const state = { cat: "all", level: "all", q: "" };

  const cardHTML = (a) => {
    const done = doneIds.includes(a.id);
    const cat = CATEGORIES.find((c) => c.id === a.cat);
    const dot = cat ? (HUE[cat.color] || "var(--acc)") : "var(--acc)";
    return (
      '<div class="arse-card ld-card' + (done ? " ld-done" : "") + '" data-sec="' + esc(a.sec) + '" data-id="' + esc(a.id) + '" style="cursor:pointer">' +
        '<div class="an">' + esc(a.title) + '</div>' +
        '<div class="ad">' + esc(a.desc) + '</div>' +
        '<div class="au" style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-top:6px">' +
          '<span class="chip" style="font-size:.62rem"><span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:' + dot + ';margin-right:5px;vertical-align:middle"></span>' + esc(cat ? cat.name : a.cat) + '</span>' +
          '<span class="chip" style="font-size:.62rem">' + esc(a.level) + '</span>' +
          '<span style="color:var(--mut);font-size:.72rem">~' + a.mins + ' min</span>' +
          '<span style="flex:1"></span>' +
          '<button class="ld-mark" data-id="' + esc(a.id) + '" style="font-size:.7rem;border:1px solid var(--line);background:transparent;color:' + (done ? "var(--acc)" : "var(--mut)") + ';border-radius:6px;padding:3px 9px;cursor:pointer">' + (done ? "Done ✓" : "Mark done") + '</button>' +
        '</div>' +
      '</div>'
    );
  };

  const gridHTML = () => {
    const list = filterActivities(acts, state);
    if (!list.length) return '<p class="muted" style="padding:24px 0">Nothing matches those filters. Try clearing the search or picking a different collection.</p>';
    return '<div class="arse-grid">' + list.map(cardHTML).join("") + "</div>";
  };

  const progHTML = () => {
    const st = progressStats(acts, doneIds);
    const lh = loadLearn();
    const catsStarted = Object.values(st.byCat).filter((c) => c.total && c.done).length;
    const tile = (big, small) =>
      '<div class="panel" style="flex:1;min-width:150px;padding:14px 16px">' +
        '<div style="font-size:1.5rem;font-weight:700;color:var(--acc);line-height:1.1">' + big + '</div>' +
        '<div class="muted" style="font-size:.78rem;margin-top:2px">' + small + '</div>' +
      '</div>';
    return (
      tile(st.done + " / " + st.total, "Activities completed (" + st.pct + "%)") +
      tile(catsStarted + " / " + cats.length, "Collections started") +
      tile(lh.xp ? lh.xp.toLocaleString() + " XP" : "—", lh.xp ? "Learn Hub rank: " + rankOf(lh.xp) : "Learn Hub not started") +
      tile(lh.streak ? lh.streak + "×" : "—", "Day streak")
    );
  };

  const chipRow = (id, current, items) =>
    '<div class="cs-filter" data-filter="' + id + '">' +
      '<button class="chip' + (current === "all" ? " on" : "") + '" data-v="all">All</button>' +
      items.map((it) => '<button class="chip' + (current === it.v ? " on" : "") + '" data-v="' + esc(it.v) + '">' + esc(it.label) + '</button>').join("") +
    '</div>';

  main.innerHTML =
    '<style>.ld-card.ld-done{border-color:var(--acc)!important}.ld-card.ld-done .an::after{content:" \\2713";color:var(--acc)}.ld-hero{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0 20px}</style>' +
    '<h1 class="pg-h1">Learn &amp; Do</h1>' +
    '<p class="muted pg-sub">Everything on Darknode, organized into things you can actually do. Pick a collection, filter by level or time, and check items off as you go &mdash; ' + acts.length + ' hands-on activities across ' + cats.length + ' collections, all inside the console.</p>' +
    '<div class="ld-hero" id="ldProg">' + progHTML() + '</div>' +
    '<h2 class="pg-h2" style="margin:6px 0 8px">Jump back in</h2>' +
    '<div class="cs-filter" style="margin-bottom:18px">' +
      '<button class="chip" data-sec="learn">Learn Hub</button>' +
      '<button class="chip" data-sec="cyberrange">Cyber Range</button>' +
      '<button class="chip" data-sec="crucible">CRUCIBLE wargame</button>' +
      '<button class="chip" data-sec="securityquiz">Take a quiz</button>' +
      '<button class="chip" data-sec="ai">Ask Darknode AI</button>' +
    '</div>' +
    '<h2 class="pg-h2" style="margin:6px 0 10px">Things to do</h2>' +
    '<div style="display:flex;flex-direction:column;gap:8px;margin-bottom:6px">' +
      chipRow("cat", state.cat, cats.map((c) => ({ v: c.id, label: c.name }))) +
      chipRow("level", state.level, LEVELS.map((l) => ({ v: l.id, label: l.name }))) +
    '</div>' +
    '<input id="ldSearch" type="search" placeholder="Search activities…" style="width:100%;max-width:420px;margin:4px 0 16px;padding:9px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:inherit;font:inherit">' +
    '<div id="ldGrid">' + gridHTML() + "</div>";

  const grid = main.querySelector("#ldGrid");
  const prog = main.querySelector("#ldProg");
  const refreshGrid = () => { grid.innerHTML = gridHTML(); };
  const refreshProg = () => { prog.innerHTML = progHTML(); };

  // filter chip rows (category + level)
  main.querySelectorAll('.cs-filter[data-filter]').forEach((row) => {
    row.addEventListener("click", (e) => {
      const b = e.target.closest(".chip"); if (!b) return;
      const key = row.dataset.filter;
      state[key === "cat" ? "cat" : "level"] = b.dataset.v;
      row.querySelectorAll(".chip").forEach((x) => x.classList.toggle("on", x === b));
      refreshGrid();
    });
  });

  // search
  const search = main.querySelector("#ldSearch");
  if (search) search.addEventListener("input", () => { state.q = search.value; refreshGrid(); });

  // quick-jump chips (data-sec, no data-filter row)
  main.querySelectorAll('.cs-filter:not([data-filter]) .chip[data-sec]').forEach((b) => {
    b.addEventListener("click", () => navTo(b.dataset.sec));
  });

  // grid: mark-done buttons and card navigation
  grid.addEventListener("click", (e) => {
    const mark = e.target.closest(".ld-mark");
    if (mark) {
      e.stopPropagation();
      const id = mark.dataset.id;
      if (doneIds.includes(id)) doneIds = doneIds.filter((x) => x !== id);
      else doneIds = doneIds.concat([id]);
      saveDone(doneIds);
      refreshGrid();
      refreshProg();
      return;
    }
    const card = e.target.closest(".ld-card[data-sec]");
    if (card) navTo(card.dataset.sec);
  });
}
