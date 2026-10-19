// MonitorDO (Deck D4): one Durable Object per workspace that runs scheduled security
// checks on the server, so live checks (certificate expiry, exposure, posture) keep
// running when nobody has the Deck open. It diffs each run against the last, turns real
// changes into alerts under the workspace's rules, and delivers them to Slack / Teams /
// Discord / signed webhooks with retry. State and scheduling are the DO's; the grading
// is the SAME pure engine the browser tools use (worker/checks.js), and the alert brain
// is worker/monitor-core.js — both unit-tested without a deploy.
import { runCheck, cvesFromEntities } from "./checks.js";
import { diffFindings, diffToEvents, shouldAlert, defaultAlertRules } from "./monitor-core.js";
import { buildGraphWrite } from "./monitor-graph.js";
import { deliver, RETRY_BACKOFF_MS } from "./notify.js";
import { verifyIdToken } from "./vault-auth.js";
import { isSuspended } from "./gate.js";
import { resolveWorkspaceRole, canDo } from "./workspace.js";

const WID = /^[A-Za-z0-9_-]{1,128}$/;
const HISTORY_CAP = 200, DELIVERY_CAP = 200;
const MIN_INTERVAL = 15 * 60 * 1000;   // never run a monitor more than every 15 min
const now = () => Date.now();
const uid = () => "m_" + Math.random().toString(36).slice(2, 10) + now().toString(36);

// Redact channel secrets before anything leaves the DO.
const safeChannel = (c) => ({ type: c.type, url: c.url, hasSecret: !!c.secret });
const safeMonitor = (m) => ({ ...m, channels: (m.channels || []).map(safeChannel), lastResults: undefined, graphMeta: undefined, lastResultCount: (m.lastResults || []).length });

export class MonitorDO {
  constructor(state, env) { this.state = state; this.storage = state.storage; this.env = env; }

  async _monitors() { return (await this.storage.get("monitors")) || {}; }

  // Read this workspace's own CVE inventory from its GraphDO. Safe: a MonitorDO is addressed
  // per workspace, and it reads the SAME workspace's graph (the GET pull is not uid-scoped —
  // the per-workspace DO is itself the access boundary, reachable only by server code). Used
  // only by the kev-epss check. Returns [] if the graph binding or the stored wid is missing.
  async _graphCves() {
    try {
      const wid = await this.storage.get("wid");
      if (!wid || !this.env || !this.env.GRAPH) return [];
      const stub = this.env.GRAPH.get(this.env.GRAPH.idFromName(wid));
      const res = await stub.fetch("https://graph/?since=0", { headers: { "x-graph-uid": wid } });
      if (!res.ok) return [];
      const data = await res.json().catch(() => null);
      // Exclude the monitor's OWN writes (source "monitor:*"). A kev-epss run now writes
      // VULNERABILITY(CVE) + FINDING nodes back into this same graph; re-reading them as
      // inventory would be a feedback loop — a patched CVE would never clear because the
      // monitor keeps seeing the node it authored last run. Only genuine tool/ingest sources
      // count as the workspace's real CVE inventory.
      const inventory = ((data && data.entities) || []).filter((e) => !String((e && e.source) || "").startsWith("monitor:"));
      return cvesFromEntities(inventory);
    } catch (_) { return []; }
  }
  // Push a monitor's findings into THIS workspace's GraphDO (same wid as the MonitorDO).
  // Returns { synced, error }; never throws. The per-workspace DO is itself the access
  // boundary (reachable only by server code), so the uid header is provenance, not authz.
  async _pushGraph(write, monitorId) {
    try {
      const wid = await this.storage.get("wid");
      if (!wid || !this.env || !this.env.GRAPH) return { synced: 0, error: "no graph binding" };
      const stub = this.env.GRAPH.get(this.env.GRAPH.idFromName(wid));
      const res = await stub.fetch("https://graph/", {
        method: "POST",
        body: JSON.stringify({ entities: write.entities, relationships: write.relationships }),
        headers: { "Content-Type": "application/json", "x-graph-uid": "monitor:" + monitorId },
      });
      if (!res.ok) return { synced: 0, error: "graph push " + res.status };
      const j = await res.json().catch(() => null);
      const applied = j && j.applied ? ((j.applied.entities || 0) + (j.applied.relationships || 0)) : 0;
      return { synced: applied, error: null };
    } catch (e) { return { synced: 0, error: String(e.message || e) }; }
  }

  async _put(mons) { await this.storage.put("monitors", mons); }
  async _log(key, cap, entry) {
    const list = (await this.storage.get(key)) || [];
    list.unshift(entry);
    if (list.length > cap) list.length = cap;
    await this.storage.put(key, list);
  }

  // Soonest next-due time across active monitors; sets the DO alarm to it.
  async _reschedule() {
    const mons = await this._monitors();
    let soonest = null;
    for (const m of Object.values(mons)) {
      if (m.paused) continue;
      const due = (m.lastRunAt || 0) + Math.max(m.intervalMs || 0, MIN_INTERVAL);
      if (soonest == null || due < soonest) soonest = due;
    }
    if (soonest != null) await this.storage.setAlarm(Math.max(soonest, now() + 1000));
  }

  // Run one monitor: check -> diff -> events -> alerts -> deliver. Returns a summary.
  async _runOne(m, deps, mons) {
    // One clock for the whole run: day-counts, diffs, alert windows and graph timestamps all
    // key off t0, so pinning it (deps.now, tests only) makes a run fully deterministic. In
    // production deps.now is never set, so this is the real wall clock.
    const t0 = Number.isFinite(deps.now) ? deps.now : now();
    let findings = [];
    // The kev-epss check grades the workspace's own CVE inventory, read from its graph.
    const extra = m.type === "kev-epss" ? { cves: await this._graphCves(), feedBase: deps.feedBase } : {};
    try { findings = await runCheck(m.type, m.config || {}, { fetch: deps.fetch, now: t0, ...extra }); }
    catch (e) { await this._log("history", HISTORY_CAP, { id: m.id, at: t0, error: String(e.message || e) }); return { id: m.id, error: String(e.message || e) }; }

    const diff = diffFindings(m.lastResults || [], findings);
    const events = diffToEvents(diff, m.id, t0);
    const rules = { ...defaultAlertRules(), ...(m.rules || {}) };
    const alerted = [];
    const held = [];
    for (const ev of events) {
      // carry cert window into the rule check for cert monitors
      if (m.type === "cert-expiry") { ev.kind = ev.kind === "resolved" ? "resolved" : "cert"; ev.daysToExpiry = findings.find((f) => f.key === ev.key)?.daysToExpiry; }
      // a new/worsened KEV-or-high-EPSS match alerts regardless of severity (onKev path)
      else if (m.type === "kev-epss" && ev.kind !== "resolved") ev.kind = "kev";
      const d = shouldAlert(ev, rules, t0);
      if (d.alert) alerted.push(ev); else if (d.suppressed) held.push(ev);
    }

    let delivered = 0;
    if (alerted.length && (m.channels || []).length && !rules.digest) {
      const alert = {
        title: `${m.name || m.type}: ${alerted.length} change${alerted.length === 1 ? "" : "s"}`,
        severity: alerted.map((e) => e.severity).sort((a, b) => ({ critical: 4, high: 3, medium: 2, low: 1 }[b] || 0) - ({ critical: 4, high: 3, medium: 2, low: 1 }[a] || 0))[0] || "info",
        text: `Monitor "${m.name || m.type}" reported changes.`,
        url: deps.deckUrl || undefined,
        events: alerted.map((e) => ({ kind: e.kind, severity: e.severity, title: e.title, detail: e.detail })),
      };
      for (const ch of m.channels) delivered += (await this._deliverWithRetry(ch, alert, deps)) ? 1 : 0;
    }

    // ---- feed findings into the workspace Security Graph (Trident Phase 2) ----
    // Monitor findings become ownable, SLA-tracked, correlatable FINDING entities, the
    // same shape a browser tool produces. Best-effort: a graph write failure never breaks
    // the monitor run or its alerting. See worker/monitor-graph.js for the id/clock model.
    m.graphMeta = m.graphMeta || {};
    const gm = m.graphMeta;
    for (const f of findings) if (!gm[f.key]) gm[f.key] = { firstSeen: t0, changedAt: t0 }; // new / cold-start backfill
    for (const c of diff.changed) if (gm[c.key]) gm[c.key].changedAt = t0;                   // a watched field changed
    // A resolution IS a change: advance the clock for removed findings too, or the resolved
    // record would carry the same updatedAt as the stored open one and GraphDO's wins() would
    // treat it as a tie and drop it, leaving the finding "open" (and its SLA clock running)
    // forever. (Verified defect — every cert renewal / patched CVE hit this.)
    for (const f of diff.removed) if (gm[f.key]) gm[f.key].changedAt = t0;
    // The monitor's own run state is authoritative regardless of the graph outcome, and must be
    // durable BEFORE the external graph write: a crash after the push must not resurrect a new
    // finding with a reset first-seen (SLA) clock on the retried run.
    m.lastResults = findings;
    m.lastRunAt = t0;
    let graphSynced = 0, graphError = null;
    try {
      const write = buildGraphWrite(m.id, m.name || m.type, findings, diff.removed, gm, t0);
      for (const f of diff.removed) delete gm[f.key];                                           // resolved + written — drop its clock
      if (write.entities.length || write.relationships.length) {
        if (mons) await this._put(mons);                                                        // persist the clock before the push
        const r = await this._pushGraph(write, m.id);
        graphSynced = r.synced; graphError = r.error;
      }
    } catch (e) { graphError = String(e.message || e); }

    await this._log("history", HISTORY_CAP, { id: m.id, at: t0, found: findings.length, added: diff.added.length, changed: diff.changed.length, removed: diff.removed.length, alerted: alerted.length, held: held.length, delivered, graphSynced, graphError, ms: now() - t0 });
    return { id: m.id, found: findings.length, alerted: alerted.length, delivered, graphSynced };
  }

  // One delivery with bounded retry/backoff. Each attempt is logged.
  async _deliverWithRetry(channel, alert, deps) {
    const sleep = deps.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    for (let i = 0; i < RETRY_BACKOFF_MS.length; i++) {
      if (RETRY_BACKOFF_MS[i]) await sleep(RETRY_BACKOFF_MS[i]);
      const res = await deliver(channel, alert, { fetch: deps.fetch });
      await this._log("deliveries", DELIVERY_CAP, { at: now(), type: channel.type, url: channel.url, status: res.status, ok: res.ok, attempt: i + 1, error: res.error });
      if (res.ok) return true;
    }
    return false;
  }

  // Run every monitor that is due. Called by alarm() and by an explicit run request.
  async runDue(deps = {}) {
    const mons = await this._monitors();
    const t = now();
    const ran = [];
    for (const m of Object.values(mons)) {
      if (m.paused) continue;
      const due = (m.lastRunAt || 0) + Math.max(m.intervalMs || 0, MIN_INTERVAL);
      if (deps.force || t >= due) ran.push(await this._runOne(m, deps, mons));
    }
    await this._put(mons);
    await this._reschedule();
    return { ran };
  }

  async alarm() {
    await this.state.blockConcurrencyWhile(async () => { await this.runDue({}); });
  }

  // ---- HTTP interface for the Deck (via handleMonitor) ----
  async fetch(request) {
    const reply = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
    if (!request.headers.get("x-mon-uid")) return reply({ error: "forbidden" }, 403);
    const role = request.headers.get("x-mon-role") || "viewer";
    // Remember this DO's workspace id so an alarm-time run can read the workspace's own graph.
    const widHdr = request.headers.get("x-mon-wid");
    if (widHdr) { const cur = await this.storage.get("wid"); if (cur !== widHdr) await this.storage.put("wid", widHdr); }
    let body = {};
    if (request.method === "POST") { try { body = await request.json(); } catch (_) { return reply({ error: "Invalid JSON body" }, 400); } }
    const op = body.op || "list";
    const canWrite = canDo(role, "write");

    if (op === "list") {
      const mons = await this._monitors();
      return reply({ monitors: Object.values(mons).map(safeMonitor), history: (await this.storage.get("history")) || [], deliveries: (await this.storage.get("deliveries")) || [] });
    }
    if (!canWrite) return reply({ error: "Your role (" + role + ") cannot change monitors." }, 403);

    if (op === "upsert") {
      const m = body.monitor || {};
      if (!m.type) return reply({ error: "monitor.type required" }, 400);
      const mons = await this._monitors();
      const id = m.id && mons[m.id] ? m.id : uid();
      const prev = mons[id] || {};
      mons[id] = { id, name: m.name || m.type, type: m.type, config: m.config || {}, rules: m.rules || prev.rules || {}, channels: Array.isArray(m.channels) ? m.channels : (prev.channels || []), intervalMs: Math.max(m.intervalMs || prev.intervalMs || MIN_INTERVAL, MIN_INTERVAL), paused: !!m.paused, lastRunAt: prev.lastRunAt || 0, lastResults: prev.lastResults || [], graphMeta: prev.graphMeta || {} };
      await this._put(mons); await this._reschedule();
      return reply({ monitor: safeMonitor(mons[id]) });
    }
    if (op === "pause") {
      const mons = await this._monitors(); const m = mons[body.id]; if (!m) return reply({ error: "not found" }, 404);
      m.paused = !!body.paused; await this._put(mons); await this._reschedule();
      return reply({ monitor: safeMonitor(m) });
    }
    if (op === "delete") {
      const mons = await this._monitors(); if (mons[body.id]) { delete mons[body.id]; await this._put(mons); await this._reschedule(); }
      return reply({ ok: true });
    }
    if (op === "run") {
      const r = await this.runDue({ force: true, deckUrl: body.deckUrl });
      return reply(r);
    }
    if (op === "test") {
      const ch = body.channel; if (!ch || !ch.url) return reply({ error: "channel.url required" }, 400);
      const ok = await this._deliverWithRetry(ch, { title: "Darknode test alert", severity: "info", text: "This is a test from your Deck monitor configuration.", url: body.deckUrl }, {});
      return reply({ ok });
    }
    return reply({ error: "unknown op: " + op }, 400);
  }
}

const MON_ID = WID;

// Route: POST /api/monitor/<wid>  { op, ... }. Same auth as the graph: a Firebase ID
// token, workspace role from Firestore. list needs read; everything else needs write.
export async function handleMonitor(request, env, wid, json) {
  if (!env.MONITOR) return json({ error: "Monitoring is not configured on this deployment." }, 503);
  if (!MON_ID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  const projectId = env.FIREBASE_PROJECT_ID;
  if (!projectId) return json({ error: "FIREBASE_PROJECT_ID is not set" }, 503);
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("Authorization") || "");
  if (!m) return json({ error: "Sign in required" }, 401);
  let who;
  try { who = await verifyIdToken(m[1], projectId); } catch (e) { return json({ error: "Invalid sign-in token: " + e.message }, 401); }
  if (await isSuspended(projectId, who, m[1])) return json({ error: "Your access has been suspended by an administrator." }, 403);
  let role;
  try { role = await resolveWorkspaceRole(projectId, wid, who.uid, m[1]); }
  catch (e) { return json({ error: e.message }, 502); }
  if (!role) return json({ error: "You are not a member of this workspace." }, 403);
  const bodyText = await request.text();
  if (bodyText.length > 256 * 1024) return json({ error: "Request too large." }, 413);
  const stub = env.MONITOR.get(env.MONITOR.idFromName(wid));
  const res = await stub.fetch("https://monitor/", { method: "POST", body: bodyText || "{}", headers: { "Content-Type": "application/json", "x-mon-uid": who.uid, "x-mon-role": role, "x-mon-wid": wid } });
  return json(await res.json(), res.status);
}
