// Darknode route / tool registry.
//
// auth.js currently routes with a ~156-branch if/else in show(), each branch
// dynamic-importing a module and calling its render function. That dispatch is
// invisible to the rest of the app: the sidebar, global search, breadcrumbs, the
// AI's notion of "what tools exist", and any capability gating all have to
// re-derive the same list by hand.
//
// The registry is a single declarative source of truth for routable views. A
// route is:
//   {
//     id,           // stable section id used by show() and [data-sec]
//     label,        // human title
//     category,     // grouping for the sidebar (e.g. "Recon", "Threat Intel")
//     module,       // dynamic-import specifier, e.g. "/js/port-scan.js"
//     render,       // exported render fn name (default "render")
//     keywords,     // extra search terms
//     flagship,     // boolean — featured tool
//     hidden,       // boolean — routable but not shown in nav (e.g. detail views)
//     requires,     // optional capability/flag name gating visibility
//     aliases,      // alternative ids that resolve here
//   }
//
// This module is pure mechanism — it ships no giant hardcoded catalog, so it
// can be adopted incrementally: register real routes from a manifest, let the
// sidebar/search read from here, and eventually have show() resolve() through it.

const SLUG = /^[a-z][a-z0-9-]*$/;

function required(route) {
  const errs = [];
  if (!route || typeof route !== "object") return ["route must be an object"];
  if (!SLUG.test(route.id || "")) errs.push(`invalid id "${route.id}" (kebab-case, leading letter)`);
  if (!route.label || typeof route.label !== "string") errs.push(`route "${route.id}" needs a label`);
  if (!route.module || typeof route.module !== "string") errs.push(`route "${route.id}" needs a module specifier`);
  return errs;
}

function normalize(route) {
  return {
    id: route.id,
    label: route.label,
    category: route.category || "General",
    module: route.module,
    render: route.render || "render",
    keywords: Array.isArray(route.keywords) ? route.keywords.map((k) => String(k).toLowerCase()) : [],
    flagship: !!route.flagship,
    hidden: !!route.hidden,
    requires: route.requires || null,
    aliases: Array.isArray(route.aliases) ? route.aliases.filter((a) => SLUG.test(a)) : [],
    order: Number.isFinite(route.order) ? route.order : 1000,
  };
}

export class Registry {
  constructor({ loader } = {}) {
    this._routes = new Map(); // id -> normalized route
    this._aliases = new Map(); // alias id -> canonical id
    // Injectable module loader (defaults to native dynamic import). Tests pass a
    // fake so no real modules are fetched.
    this._loader = loader || ((spec) => import(spec));
  }

  /** Register a route. Throws on invalid definition or a duplicate id/alias. */
  register(route) {
    const errs = required(route);
    if (errs.length) throw new Error("registry.register: " + errs.join("; "));
    if (this._routes.has(route.id)) throw new Error(`registry: duplicate route id "${route.id}"`);
    if (this._aliases.has(route.id)) throw new Error(`registry: id "${route.id}" collides with an existing alias`);
    const norm = normalize(route);
    for (const a of norm.aliases) {
      if (this._routes.has(a) || this._aliases.has(a)) throw new Error(`registry: alias "${a}" collides`);
    }
    this._routes.set(norm.id, norm);
    for (const a of norm.aliases) this._aliases.set(a, norm.id);
    return norm;
  }

  /** Register many; returns the count added. Throws (atomically-ish) on first bad one. */
  registerAll(routes) {
    let n = 0;
    for (const r of routes || []) { this.register(r); n++; }
    return n;
  }

  /** Resolve an id or alias to a canonical route (or null). */
  get(id) {
    if (this._routes.has(id)) return this._routes.get(id);
    const canon = this._aliases.get(id);
    return canon ? this._routes.get(canon) : null;
  }

  has(id) { return this.get(id) !== null; }

  /** All routes, sorted by (order, label). Pass { includeHidden } to include hidden. */
  list({ includeHidden = false } = {}) {
    const out = [...this._routes.values()].filter((r) => includeHidden || !r.hidden);
    return out.sort((a, b) => a.order - b.order || a.label.localeCompare(b.label));
  }

  /** Distinct category names in display order. */
  categories({ includeHidden = false } = {}) {
    const seen = new Map();
    for (const r of this.list({ includeHidden })) {
      if (!seen.has(r.category)) seen.set(r.category, r.order);
      else seen.set(r.category, Math.min(seen.get(r.category), r.order));
    }
    return [...seen.entries()].sort((a, b) => a[1] - b[1] || a[0].localeCompare(b[0])).map(([c]) => c);
  }

  /** Routes grouped by category: { category: [routes] }. */
  byCategory(opts) {
    const groups = {};
    for (const r of this.list(opts)) (groups[r.category] ||= []).push(r);
    return groups;
  }

  /** Flagship routes only. */
  flagships() { return this.list().filter((r) => r.flagship); }

  /**
   * Fuzzy-ish search over id/label/category/keywords. Returns scored matches
   * (highest first). Score weights an exact id/label hit above a keyword hit.
   */
  search(query, { includeHidden = false, limit = 25 } = {}) {
    const q = String(query || "").trim().toLowerCase();
    if (!q) return [];
    const scored = [];
    for (const r of this.list({ includeHidden })) {
      let score = 0;
      const label = r.label.toLowerCase();
      if (r.id === q || label === q) score += 100;
      else if (label.startsWith(q) || r.id.startsWith(q)) score += 60;
      else if (label.includes(q) || r.id.includes(q)) score += 40;
      if (r.category.toLowerCase().includes(q)) score += 15;
      for (const k of r.keywords) {
        if (k === q) score += 25;
        else if (k.includes(q)) score += 10;
      }
      if (r.flagship && score > 0) score += 5;
      if (score > 0) scored.push({ route: r, score });
    }
    scored.sort((a, b) => b.score - a.score || a.route.label.localeCompare(b.route.label));
    return scored.slice(0, limit).map((s) => s.route);
  }

  /**
   * Resolve a route and load its module, returning the render function.
   * @returns {Promise<{ route, render:Function }>}
   * Throws if the route is unknown or the module lacks the named export.
   */
  async load(id) {
    const route = this.get(id);
    if (!route) throw new Error(`registry: no route "${id}"`);
    const mod = await this._loader(route.module);
    const fn = mod && mod[route.render];
    if (typeof fn !== "function") {
      throw new Error(`registry: module "${route.module}" has no export "${route.render}"`);
    }
    return { route, render: fn };
  }

  get size() { return this._routes.size; }
}

// App-wide singleton. Real routes are registered from a manifest during boot.
export const registry = new Registry();
