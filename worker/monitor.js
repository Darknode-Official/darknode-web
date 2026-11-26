// MonitorDO (Deck D4): one Durable Object per workspace that runs scheduled security
// checks on the server, so live checks (certificate expiry, exposure, posture) keep
// running when nobody has the Deck open. It diffs each run against the last, turns real
// changes into alerts under the workspace's rules, and delivers them to Slack / Teams /
// Discord / signed webhooks / the account's own email with retry. On the Free plan it runs
// the one-domain watch (worker/free-watch.js). State and scheduling are the DO's; the grading
// is the SAME pure engine the browser tools use (worker/checks.js), and the alert brain
// is worker/monitor-core.js — both unit-tested without a deploy.
import { runCheck, cvesFromEntities, hostOnly } from "./checks.js";
import { diffFindings, diffToEvents, shouldAlert, defaultAlertRules } from "./monitor-core.js";
import { buildGraphWrite } from "./monitor-graph.js";
import { deliver, RETRY_BACKOFF_MS } from "./notify.js";
import { requireUser } from "./auth.js";
import { resolveWorkspaceRole, canDo, isPersonalWorkspace, isTeamWorkspaceId } from "./workspace.js";
import { featureDenied } from "./plan.js";
import { workspaceTier, liveTier } from "./plan-share.js";
import { readCapped } from "./body-cap.js";
import { FREE_WATCH, FREE_TEAM_MSG, freeWatchDenied, freeAllowed } from "./free-watch.js";
import { ALERT_EMAILS_PER_DAY, buildAlertEmail, buildTestEmail, maskEmail, recipient, sendEmail, stopToken, stopUrl, STOP_PATH } from "./alert-email.js";
import { timingSafeEqual } from "./keys-core.js";
import { unsubSecret } from "./digest.js";
import { takeDaily } from "./quota.js";

const WID = /^[A-Za-z0-9_-]{1,128}$/;
const HISTORY_CAP = 200, DELIVERY_CAP = 200;
const MIN_INTERVAL = 15 * 60 * 1000;   // never run a monitor more than every 15 min
const now = () => Date.now();
const uid = () => "m_" + Math.random().toString(36).slice(2, 10) + now().toString(36);

// Redact channel secrets before anything leaves the DO.
// A Slack/Discord/Teams webhook URL is itself the credential: viewers see only its host.
const hideUrl = (u) => { try { const x = new URL(u); return x.origin + (x.pathname.length > 1 || x.search ? "/…" : ""); } catch (_) { return "…"; } };
// An email channel's address is shown in full only to its own account; anyone else sees it masked.
const safeChannel = (c, full = true, viewer = "") => c.type === "email"
  ? { type: "email", to: viewer && viewer === c.uid ? c.to : maskEmail(c.to), mine: !!viewer && viewer === c.uid, hasSecret: false }
  : { type: c.type, url: full ? c.url : hideUrl(c.url), hasSecret: !!c.secret };
// next run: a run held for the plan waits a full interval too, or the alarm would refire every second
const dueAt = (m) => Math.max(m.lastRunAt || 0, m.planHeldAt || 0) + Math.max(m.intervalMs || 0, MIN_INTERVAL);
const safeMonitor = (m, full = true, viewer = "") => ({ ...m, channels: (m.channels || []).map((c) => safeChannel(c, full, viewer)), lastResults: undefined, graphMeta: undefined, posture: undefined, lastResultCount: (m.lastResults || []).length });

// The channels a saved monitor keeps. An email channel never takes its recipient from the request:
// it is the verified address of the account saving the monitor (x-mon-email, which handleMonitor
// sets from the ID token only when email_verified is true). At most one email channel per monitor.
// -> { channels } | { error }
function saveChannels(given, prev, uid, email) {
  if (!Array.isArray(given)) return { channels: prev || [] };
  const out = [];
  let mail = false;
  for (const c of given) {
    if (!c || typeof c !== "object") continue;
    if (c.type !== "email") { out.push(c); continue; }
    if (mail) continue;
    if (!email) return { error: "Verify your account email address first, then turn on email alerts." };
    mail = true;
    out.push({ type: "email", to: email, uid });
  }
  return { channels: out };
}

// An alerted event plus the finding fields the alert email explains (what changed, why it matters,
// the fix). SPF and DMARC events also carry the record's state on the previous run and now.
function alertEvent(e, f = {}, before = {}, after = {}) {
  const out = { kind: e.kind, severity: e.severity, title: e.title, detail: e.detail, key: e.key };
  for (const k of ["domain", "check", "advice", "daysToExpiry", "notAfter", "issuer", "cve", "dueDate", "epss"]) if (f[k] != null && f[k] !== "") out[k] = f[k];
  const part = f.check === "SPF" ? "spf" : f.check === "DMARC" ? "dmarc" : "";
  if (part && f.domain) {
    const was = (before[f.domain] || {})[part], now = (after[f.domain] || {})[part];
    if (was && now && was !== now) { out.was = was; out.now = now; }
    if (part === "dmarc" && (after[f.domain] || {}).dmarcAt) out.recordAt = after[f.domain].dmarcAt;
  }
  return out;
}

export class MonitorDO {
  constructor(state, env) { this.state = state; this.storage = state.storage; this.env = env; }

  // Null-proto map: a monitor id comes from the request body, so "__proto__"/
  // "constructor" must be an ordinary own entry, never reach Object.prototype.
  async _monitors() { return Object.assign(Object.create(null), await this.storage.get("monitors")); }

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
      if (!res.ok) return null; // could not read the inventory: not the same as an empty one
      const data = await res.json().catch(() => null);
      if (!data) return null;
      // Exclude the monitor's OWN writes (source "monitor:*"). A kev-epss run now writes
      // VULNERABILITY(CVE) + FINDING nodes back into this same graph; re-reading them as
      // inventory would be a feedback loop — a patched CVE would never clear because the
      // monitor keeps seeing the node it authored last run. Only genuine tool/ingest sources
      // count as the workspace's real CVE inventory.
      const inventory = ((data && data.entities) || []).filter((e) => !String((e && e.source) || "").startsWith("monitor:"));
      return cvesFromEntities(inventory);
    } catch (_) { return null; }
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
      const due = dueAt(m);
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
    // A lookup that got no answer is not a clean result: diffing it would resolve every open
    // finding (closing them in the graph) and alert them all as new once the source is back.
    try {
      if (m.type === "kev-epss" && extra.cves == null) throw new Error("could not read the workspace's CVE inventory; nothing changed this run");
      findings = await runCheck(m.type, m.config || {}, { fetch: deps.fetch, now: t0, ...extra });
      if (findings && findings.unreachable) throw new Error(m.type === "email-posture" ? "no DNS resolver answered; nothing changed this run" : "a feed did not answer; nothing changed this run");
    }
    catch (e) { await this._log("history", HISTORY_CAP, { id: m.id, at: t0, error: String(e.message || e) }); return { id: m.id, error: String(e.message || e) }; }

    // a domain whose lookup got no answer keeps its last finding as it was (checks.js held)
    const skipped = (findings.unknown || []).length, checked = findings.checked;
    const postureBefore = m.posture || {}, postureNow = findings.posture || {}; // SPF/DMARC state (email-posture)
    const prevByKey = new Map((m.lastResults || []).map((f) => [f.key, f]));
    findings = [...findings, ...(findings.held || []).filter((k) => prevByKey.has(k) && !findings.some((f) => f.key === k)).map((k) => prevByKey.get(k))];
    const diff = diffFindings(m.lastResults || [], findings);
    const events = diffToEvents(diff, m.id, t0);
    const rules = { ...defaultAlertRules(), ...(m.rules || {}) };
    // the cert monitor only reports certificates inside ITS warn window (the Deck form sets it):
    // alerting on the 21-day default meant a 40-day finding under warnDays 60 never alerted
    if (m.type === "cert-expiry" && m.config && Number(m.config.warnDays) > 0 && !(m.rules && m.rules.certExpiryDays != null)) rules.certExpiryDays = Number(m.config.warnDays);
    const alerted = [];
    const held = [];
    for (const ev of events) {
      // carry cert window into the rule check for cert monitors
      // Only new and worsened events take the cert/KEV path. A "changed" event here is just the
      // title moving (expires in 10 days -> 9, EPSS 61% -> 62%) and re-alerted every run.
      const real = ev.kind === "new" || ev.kind === "worsened";
      if (m.type === "cert-expiry" && real) { ev.kind = "cert"; ev.daysToExpiry = findings.find((f) => f.key === ev.key)?.daysToExpiry; }
      // a new/worsened KEV-or-high-EPSS match alerts regardless of severity (onKev path)
      else if (m.type === "kev-epss" && real) ev.kind = "kev";
      // once a domain has a baseline (a run where its records answered), any new or worsened
      // record on it is drift and alerts regardless of severity (onDrift). A domain's first
      // answered run, including one added to an existing monitor, obeys minSeverity.
      else if (m.type === "email-posture" && real && (m.baselined || []).includes((findings.find((f) => f.key === ev.key) || {}).domain)) ev.kind = "drift";
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
        events: alerted.map((e) => alertEvent(e, findings.find((f) => f.key === e.key), postureBefore, postureNow)),
      };
      for (const ch of m.channels) delivered += (await this._deliverWithRetry(ch, alert, { ...deps, now: t0 }, m)) ? 1 : 0;
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
    // A resolution must survive a failed graph push. Removed findings go into a pending-
    // resolution queue (keeping their clocks) and are re-emitted every run until the push is
    // acked — otherwise one best-effort write failure would leave the finding "open" with its
    // SLA clock running forever, because m.lastResults below drops it and diffFindings would
    // never surface it as removed again. A finding that reappears leaves the queue.
    m.pendingResolved = m.pendingResolved || {};
    for (const f of diff.removed) if (!m.pendingResolved[f.key]) { m.pendingResolved[f.key] = f; if (gm[f.key]) gm[f.key].changedAt = t0; } // resolution IS a change: advance the clock once, then keep it stable so re-pushes are idempotent ties
    for (const key of Object.keys(m.pendingResolved)) if (findings.some((f) => f.key === key)) delete m.pendingResolved[key]; // came back → the open path owns it again
    const resolvedList = Object.values(m.pendingResolved);
    // The monitor's own run state is authoritative regardless of the graph outcome, and must be
    // durable BEFORE the external graph write: a crash after the push must not resurrect a new
    // finding with a reset first-seen (SLA) clock on the retried run.
    m.lastResults = findings;
    m.lastRunAt = t0;
    // a domain removed from the monitor loses its baseline, so re-adding it starts fresh
    if (checked) {
      const watched = new Set(((m.config && m.config.domains) || []).map(hostOnly));
      m.baselined = [...new Set([...(m.baselined || []), ...checked])].filter((d) => watched.has(d));
      m.posture = Object.fromEntries(Object.entries({ ...postureBefore, ...postureNow }).filter(([d]) => watched.has(d)));
    }
    let graphSynced = 0, graphError = null;
    try {
      const write = buildGraphWrite(m.id, m.name || m.type, findings, resolvedList, gm, t0);
      if (write.entities.length || write.relationships.length) {
        if (mons) await this._put(mons);                                                        // persist clocks + pending queue before the push
        const r = await this._pushGraph(write, m.id);
        graphSynced = r.synced; graphError = r.error;
        if (!graphError) {                                                                       // acked → safe to forget these resolutions and their clocks
          for (const f of resolvedList) { delete m.pendingResolved[f.key]; if (gm[f.key]) delete gm[f.key]; }
          if (mons) await this._put(mons);
        }
      }
    } catch (e) { graphError = String(e.message || e); }

    await this._log("history", HISTORY_CAP, { id: m.id, at: t0, found: findings.length, added: diff.added.length, changed: diff.changed.length, removed: diff.removed.length, alerted: alerted.length, held: held.length, ...(skipped ? { skipped } : {}), delivered, graphSynced, graphError, ms: now() - t0 });
    return { id: m.id, found: findings.length, alerted: alerted.length, delivered, graphSynced };
  }

  // One delivery with bounded retry/backoff. Each attempt is logged.
  async _deliverWithRetry(channel, alert, deps, monitor) {
    if (channel && channel.type === "email") return this._deliverEmail(channel, alert, deps, monitor);
    const sleep = deps.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    for (let i = 0; i < RETRY_BACKOFF_MS.length; i++) {
      if (RETRY_BACKOFF_MS[i]) await sleep(RETRY_BACKOFF_MS[i]);
      const res = await deliver(channel, alert, { fetch: deps.fetch });
      await this._log("deliveries", DELIVERY_CAP, { at: now(), type: channel.type, url: channel.url, status: res.status, ok: res.ok, attempt: i + 1, error: res.error });
      if (deps.report) deps.report.last = res; // the caller (a channel test) can say why it failed
      if (res.ok) return true;
    }
    return false;
  }

  // An email alert to the account's own address (alert-email.js). Every outcome lands in the
  // delivery log: a recipient that cannot be confirmed, the daily cap, and each send attempt.
  // The cap is taken once per alert (not per retry) and given back when every attempt fails.
  async _deliverEmail(channel, alert, deps, monitor) {
    const env = this.env || {}, t0 = Number.isFinite(deps.now) ? deps.now : now();
    const sleep = deps.sleep || ((ms) => new Promise((r) => setTimeout(r, ms)));
    const quota = deps.emailQuota || ((key, limit, at, refund) => takeDaily(env, key, limit, at, refund));
    const log = async (res, attempt) => {
      await this._log("deliveries", DELIVERY_CAP, { at: now(), type: "email", url: "", to: maskEmail(channel.to), status: res.status || 0, ok: !!res.ok, attempt, error: res.error });
      if (deps.report) deps.report.last = res;
    };
    const who = await recipient(env, channel, deps);
    if (who.error) { await log({ ok: false, status: 0, error: who.error }, 1); return false; }
    const key = "alert-email:" + channel.uid;
    const q = await quota(key, ALERT_EMAILS_PER_DAY, t0, false);
    if (!q.ok) { await log({ ok: false, status: 429, error: "Daily alert email limit reached (" + ALERT_EMAILS_PER_DAY + " a day). This change is listed in the Deck under Monitors; email alerts resume tomorrow (UTC)." }, 1); return false; }
    const wid = (await this.storage.get("wid")) || "";
    const stop = wid ? await stopUrl(env, wid, channel.uid) : "";
    const mail = alert.test
      ? buildTestEmail({ stopUrl: stop, sent: q.used, limit: q.limit || ALERT_EMAILS_PER_DAY, now: t0 })
      : buildAlertEmail({ monitor: monitor || {}, events: alert.events || [], stopUrl: stop, sent: q.used, limit: q.limit || ALERT_EMAILS_PER_DAY, now: t0 });
    const idempotencyKey = "dn-" + ((monitor && monitor.id) || "test") + "-" + t0 + "-" + channel.uid;
    for (let i = 0; i < RETRY_BACKOFF_MS.length; i++) {
      if (RETRY_BACKOFF_MS[i]) await sleep(RETRY_BACKOFF_MS[i]);
      const res = await (deps.sendEmail || sendEmail)(env, { to: who.to, ...mail, stop, idempotencyKey }, deps.fetch || fetch);
      await log(res, i + 1);
      if (res.ok) return true;
    }
    try { await quota(key, ALERT_EMAILS_PER_DAY, t0, true); } catch (_) {} // nothing was delivered: it does not count
    return false;
  }

  // Run every monitor that is due. Called by alarm() and by an explicit run request.
  async runDue(deps = {}) {
    const mons = await this._monitors();
    const t = now();
    const ran = [];
    for (const m of Object.values(mons)) {
      if (m.paused) continue;
      if (deps.only && !deps.only.has(m.id)) continue; // a Free plan "Run now" runs the watch only
      if (!deps.force && t < dueAt(m)) continue;
      // scheduled runs re-check the plan of whoever set the monitor up: a downgrade (or the
      // workspace owner turning plan sharing off) holds it until someone with the plan resumes
      if (!deps.force && deps.planOk && !(await deps.planOk(m))) {
        m.planHeld = true; m.planHeldAt = t;
        await this._log("history", HISTORY_CAP, { id: m.id, at: t, error: "held: the plan of the person who set this monitor up no longer includes monitoring" });
        continue;
      }
      if (m.planHeld) { delete m.planHeld; delete m.planHeldAt; }
      ran.push(await this._runOne(m, deps, mons));
    }
    await this._put(mons);
    await this._reschedule();
    return { ran };
  }

  async alarm() {
    const wid = await this.storage.get("wid");
    await this.state.blockConcurrencyWhile(async () => {
      // below Pro, only the Free plan's one-domain watch keeps running (personal workspace only)
      const free = wid && !isTeamWorkspaceId(wid) ? freeAllowed(await this._monitors()) : new Set();
      const planOk = async (m) => { if (!wid) return true; const t = await liveTier(this.env, wid, m.by || "", this.planOpts); return t === null || !featureDenied("monitors", t) || free.has(m.id); };
      await this.runDue({ planOk });
    });
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
    const caller = request.headers.get("x-mon-uid");
    // x-mon-plan "free": the caller is below Pro, so only the one-domain watch is allowed (free-watch.js).
    // x-mon-email: the caller's verified address, the only one an email channel may use.
    const free = request.headers.get("x-mon-plan") === "free";
    let email = ""; try { email = decodeURIComponent(request.headers.get("x-mon-email") || ""); } catch (_) {}
    const planReply = (error) => reply({ error, plan: true }, 402);

    if (op === "list") {
      const mons = await this._monitors();
      const deliveries = (await this.storage.get("deliveries")) || [];
      return reply({ monitors: Object.values(mons).map((x) => safeMonitor(x, canWrite, caller)), history: (await this.storage.get("history")) || [], deliveries: canWrite ? deliveries : deliveries.map((d) => ({ ...d, url: hideUrl(d.url) })) });
    }
    // The stop link in an alert email (handleWatchStop, never reachable through handleMonitor):
    // pause every monitor here that emails that account.
    if (op === "stopEmail" && request.headers.get("x-mon-stop") === "1") {
      return this.state.blockConcurrencyWhile(async () => {
        const mons = await this._monitors(), paused = [];
        for (const m of Object.values(mons)) {
          if (!(m.channels || []).some((c) => c && c.type === "email" && c.uid === body.uid)) continue;
          if (!m.paused) { m.paused = true; paused.push(m.name || m.type); }
        }
        if (paused.length) { await this._put(mons); await this._reschedule(); }
        return reply({ ok: true, paused });
      });
    }
    if (!canWrite) return reply({ error: "Your role (" + role + ") cannot change monitors." }, 403);

    // Serialize every mutating op. Each does a read-modify-write on `mons`, and run/test
    // hold that snapshot across long non-storage awaits (network checks + delivery) during
    // which the DO input gate would otherwise open — so a concurrent request could write a
    // stale snapshot (clobbering an interleaved upsert/pause/delete and resurrecting
    // resolved findings' SLA clocks) and two runs could double-deliver the same change.
    return this.state.blockConcurrencyWhile(async () => {
    if (op === "upsert") {
      const m = body.monitor || {};
      if (!m.type) return reply({ error: "monitor.type required" }, 400);
      const mons = await this._monitors();
      const id = m.id && mons[m.id] ? m.id : uid();
      const prev = mons[id] || {};
      const ch = saveChannels(m.channels, prev.channels, caller, email);
      if (ch.error) return reply({ error: ch.error }, 400);
      // the Free watch alerts by email: that is its default channel
      if (free && !ch.channels.length && Array.isArray(m.channels)) {
        if (!email) return reply({ error: "Verify your account email address first: the Free watch sends its alerts there." }, 400);
        ch.channels.push({ type: "email", to: email, uid: caller });
      }
      const minInterval = free ? FREE_WATCH.minIntervalMs : MIN_INTERVAL;
      const next = { id, name: m.name || m.type, type: m.type, config: m.config || {}, rules: m.rules || prev.rules || {}, channels: ch.channels, intervalMs: Math.max(m.intervalMs || prev.intervalMs || minInterval, minInterval), paused: !!m.paused, by: caller, createdAt: prev.createdAt || now(), lastRunAt: prev.lastRunAt || 0, lastResults: prev.lastResults || [], graphMeta: prev.graphMeta || {}, baselined: prev.baselined || [], posture: prev.posture || {} };
      if (free) { const no = freeWatchDenied(next, Object.values(mons).filter((x) => x.id !== id)); if (no) return planReply(no); }
      mons[id] = next;
      await this._put(mons); await this._reschedule();
      return reply({ monitor: safeMonitor(mons[id], true, caller) });
    }
    if (op === "pause") {
      const mons = await this._monitors(); const m = mons[body.id]; if (!m) return reply({ error: "not found" }, 404);
      // resuming on the Free plan: only the one-domain watch
      if (free && body.paused === false && !freeAllowed(mons).has(m.id)) return planReply("This monitor is not part of the Free plan's one-domain watch, so it cannot be resumed on the Free plan. Request an upgrade under Plans.");
      m.paused = !!body.paused;
      if (!m.paused) { m.by = caller; delete m.planHeld; delete m.planHeldAt; } // resuming passed the plan check: the resumer now carries it
      await this._put(mons); await this._reschedule();
      return reply({ monitor: safeMonitor(m, true, caller) });
    }
    if (op === "delete") {
      const mons = await this._monitors(); if (mons[body.id]) { delete mons[body.id]; await this._put(mons); await this._reschedule(); }
      return reply({ ok: true });
    }
    if (op === "run") {
      if (!free) return reply(await this.runDue({ force: true, deckUrl: body.deckUrl }));
      // Free: the watch only, and at most once per 10 minutes (each run reads public CT logs and DNS)
      const last = (await this.storage.get("freeRunAt")) || 0, wait = last + FREE_WATCH.manualRunGapMs - now();
      if (wait > 0) return reply({ error: "The watch ran a few minutes ago. Run it again in " + Math.ceil(wait / 60000) + " minute" + (Math.ceil(wait / 60000) === 1 ? "" : "s") + "." }, 429);
      await this.storage.put("freeRunAt", now());
      return reply(await this.runDue({ force: true, deckUrl: body.deckUrl, only: freeAllowed(await this._monitors()) }));
    }
    if (op === "test") {
      const given = body.channel || {};
      if (free && given.type !== "email") return planReply("On the Free plan, alerts go to your account email. Slack, Teams, Discord and webhook alerts are part of the Pro plan.");
      if (given.type === "email") {
        // a test email goes to the caller's own verified address, never to one in the request
        if (!email) return reply({ error: "Verify your account email address first, then test email alerts." }, 400);
        const report = {};
        const ok = await this._deliverEmail({ type: "email", to: email, uid: caller }, { test: true }, { report });
        const last = report.last || {};
        return reply(ok ? { ok, to: email } : { ok, status: last.status || 0, error: last.error || "" });
      }
      const ch = given; if (!ch.url) return reply({ error: "channel.url required" }, 400);
      const report = {};
      const ok = await this._deliverWithRetry(ch, { title: "Darknode test alert", severity: "info", text: "This is a test from your Deck monitor configuration.", url: body.deckUrl }, { report });
      const last = report.last || {};
      return reply(ok ? { ok } : { ok, status: last.status || 0, error: last.error || "" });
    }
    return reply({ error: "unknown op: " + op }, 400);
    });
  }
}

const MON_ID = WID;

// Route: POST /api/monitor/<wid>  { op, ... }. Same auth as the graph: a Firebase ID
// token, workspace role from Firestore. list needs read; everything else needs write.
const MON_PAID_OPS = new Set(["upsert", "run", "test"]);

export async function handleMonitor(request, env, wid, json) {
  if (!env.MONITOR) return json({ error: "Monitoring is not configured on this deployment." }, 503);
  if (!MON_ID.test(wid)) return json({ error: "Invalid workspace id" }, 400);
  if (request.method !== "POST") return json({ error: "POST only" }, 405);
  const who = await requireUser(request, env, json);
  if (who.err) return who.err;
  const projectId = env.FIREBASE_PROJECT_ID;
  let role;
  try { role = await resolveWorkspaceRole(projectId, wid, who.uid, who.token); }
  catch (e) { return json({ error: e.message }, 502); }
  if (!role) return json({ error: "You are not a member of this workspace." }, 403);
  const bodyText = await readCapped(request, 256 * 1024);
  if (bodyText === null) return json({ error: "Request too large." }, 413);
  // Adding, editing or running a monitor needs the plan; list, pause and delete stay open
  // so someone who downgrades can still see and clean up what they had (but not resume).
  // Resuming a paused monitor restarts paid work, so it needs the plan too.
  // Below Pro, the personal workspace gets the Free plan's one-domain watch: the request goes on
  // marked x-mon-plan "free" and the MonitorDO enforces the watch's limits (free-watch.js) in the
  // same step as the write. A team workspace has no Free watch.
  let op = "", resume = false; try { const b = JSON.parse(bodyText || "{}") || {}; op = String(b.op || ""); resume = op === "pause" && b.paused === false; } catch (_) {}
  let plan = "";
  if (MON_PAID_OPS.has(op) || resume) {
    const planMsg = featureDenied("monitors", await workspaceTier(env, wid, who));
    if (planMsg) {
      if (!isPersonalWorkspace(wid, who.uid)) return json({ error: FREE_TEAM_MSG, plan: true }, 402);
      plan = "free";
    }
  }
  // the only address an email channel may use: the caller's own, from the verified ID token
  const verified = !!(who.claims && who.claims.email_verified === true) && !!who.email;
  const headers = { "Content-Type": "application/json", "x-mon-uid": who.uid, "x-mon-role": role, "x-mon-wid": wid };
  if (plan) headers["x-mon-plan"] = plan;
  if (verified) headers["x-mon-email"] = encodeURIComponent(String(who.email).trim());
  const stub = env.MONITOR.get(env.MONITOR.idFromName(wid));
  const res = await stub.fetch("https://monitor/", { method: "POST", body: bodyText || "{}", headers });
  return json(await res.json(), res.status);
}

// ---- the stop link in an alert email: GET /api/watch/stop?w=<wid>&u=<uid>&t=<token> ----------
// GET shows a page with one button (a link scanner that opens it does not stop anything); POST,
// from that button or a mail client's List-Unsubscribe one-click, pauses every monitor in the
// workspace that emails that account. The token is an HMAC of (workspace, account), so a link
// cannot be altered to stop someone else's alerts.
const page = (title, msg, form = "") => new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${esc(title)} · Darknode</title><body style="margin:0;font:15px/1.55 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:#f7f7f4;color:#1d1c1a;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px 16px;box-sizing:border-box"><main style="width:100%;max-width:460px"><div style="font-weight:800;font-size:16px;letter-spacing:-.01em;margin:0 4px 14px">Darknode</div><div style="background:#fff;border:1px solid #e6e4de;border-radius:12px;padding:28px"><h1 style="font-size:20px;line-height:1.3;margin:0 0 8px;letter-spacing:-.01em">${esc(title)}</h1><p style="margin:0;color:#56544f">${msg}</p>${form}</div></main></body></html>`, { headers: { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store", "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" } });
const esc = (s) => String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const BTN = "display:inline-block;border:0;background:#2552c6;color:#fff;font:600 14px/1 -apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif;padding:12px 18px;border-radius:8px;cursor:pointer";
const DECK = "https://darknode.ai/monitors";

export async function handleWatchStop(request, env) {
  const u = new URL(request.url), wid = u.searchParams.get("w") || "", uidQ = u.searchParams.get("u") || "", t = u.searchParams.get("t") || "";
  const secret = unsubSecret(env || {});
  const ok = secret && MON_ID.test(wid) && uidQ && uidQ.length <= 128 && t && timingSafeEqual(t, await stopToken(wid, uidQ, secret));
  if (!ok) return page("Link not valid", `This link is incomplete or was not issued by Darknode. You can pause or remove a watch in the Deck under <a href="${DECK}" style="color:#2552c6">Monitors</a>.`);
  if (request.method !== "POST") {
    const action = STOP_PATH + "?w=" + encodeURIComponent(wid) + "&u=" + encodeURIComponent(uidQ) + "&t=" + encodeURIComponent(t);
    return page("Stop alert emails?", "This pauses every monitor in this workspace that emails you, so it stops checking and sending. You can resume it any time in the Deck under Monitors.",
      `<form method="post" action="${esc(action)}" style="margin:22px 0 0"><button type="submit" style="${BTN}">Stop alert emails</button></form>`);
  }
  if (!env.MONITOR) return page("Something went wrong", "Monitoring is not available right now. Try the link again later, or pause the watch in the Deck under Monitors.");
  try {
    const stub = env.MONITOR.get(env.MONITOR.idFromName(wid));
    const res = await stub.fetch("https://monitor/", { method: "POST", body: JSON.stringify({ op: "stopEmail", uid: uidQ }), headers: { "Content-Type": "application/json", "x-mon-uid": uidQ, "x-mon-role": "viewer", "x-mon-stop": "1" } });
    const out = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(String(out.error || res.status));
    const n = (out.paused || []).length;
    return page("Alert emails stopped", (n ? "Paused " + n + " monitor" + (n === 1 ? "" : "s") + ": " + esc(out.paused.slice(0, 5).join(", ")) + ". " : "Nothing here was emailing you any more. ")
      + `To start again, open the Deck, go to <a href="${DECK}" style="color:#2552c6">Monitors</a> and click Resume.`);
  } catch (_) {
    return page("Something went wrong", `We could not pause the watch just now. Try the link again, or pause it in the Deck under <a href="${DECK}" style="color:#2552c6">Monitors</a>.`);
  }
}
