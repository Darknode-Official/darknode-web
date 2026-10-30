// Monitoring brain (Deck D4). PURE — no network, no storage, no Durable Object.
// The MonitorDO (stateful, scheduled) drives these functions; keeping them pure means
// they run identically in a node test and in the worker, and a change in alert policy
// is unit-testable without a deploy.

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
export const sevRank = (s) => SEV_RANK[String(s || "").toLowerCase()] || 0;

// Fields whose change on an existing finding is worth an alert.
const WATCH_FIELDS = ["severity", "status", "title"];

function changedFields(prev, next) {
  const out = [];
  for (const f of WATCH_FIELDS) if (String(prev[f] ?? "") !== String(next[f] ?? "")) out.push(f);
  return out;
}

// diffFindings(prevList, nextList, keyOf) -> { added, removed, changed }
// Compares two monitor runs by a stable key so only real changes surface. `changed`
// entries carry the differing field names, the previous and the next finding.
export function diffFindings(prevList, nextList, keyOf = (f) => f.key) {
  const pm = new Map((prevList || []).map((f) => [keyOf(f), f]));
  const nm = new Map((nextList || []).map((f) => [keyOf(f), f]));
  const added = [], removed = [], changed = [];
  for (const [k, f] of nm) {
    if (!pm.has(k)) { added.push(f); continue; }
    const fields = changedFields(pm.get(k), f);
    if (fields.length) changed.push({ key: k, from: pm.get(k), to: f, fields });
  }
  for (const [k, f] of pm) if (!nm.has(k)) removed.push(f);
  // deterministic order
  const byKey = (a, b) => String(keyOf(a)).localeCompare(String(keyOf(b)));
  added.sort(byKey); removed.sort(byKey);
  changed.sort((a, b) => String(a.key).localeCompare(String(b.key)));
  return { added, removed, changed };
}

// Turn a diff into alert-candidate events. `meta` carries context used by rules
// (kev set, correlation hits, cert-expiry days, sla-breach flags) when the caller has it.
// Each event: { kind, severity, key, title, detail, at }.
export function diffToEvents(diff, monitorId, now = Date.now()) {
  const ev = [];
  const at = now;
  for (const f of diff.added) ev.push({ kind: "new", severity: f.severity, key: f.key, title: f.title, detail: `New from ${monitorId}`, at });
  for (const c of diff.changed) {
    const worsened = sevRank(c.to.severity) > sevRank(c.from.severity);
    ev.push({ kind: worsened ? "worsened" : "changed", severity: c.to.severity, key: c.key, title: c.to.title, detail: `${c.fields.join(", ")} changed`, at });
  }
  for (const f of diff.removed) ev.push({ kind: "resolved", severity: f.severity, key: f.key, title: f.title, detail: `No longer seen by ${monitorId}`, at });
  return ev;
}

// Default alert rules for a workspace. Everything off that would be noisy; a sane floor on.
export function defaultAlertRules() {
  return {
    minSeverity: "high",      // alert on new/worsened findings at or above this
    onNew: true,
    onWorsened: true,
    onResolved: false,
    onKev: true,              // a new KEV match always alerts
    onCorrelation: true,      // a new correlation chain always alerts
    onSlaBreach: true,
    certExpiryDays: 21,       // alert when a watched cert expires within N days
    onDrift: true,            // a watched DNS/email record weakened since the last run always alerts
    quietHours: null,         // { startHour, endHour } in UTC, or null
    digest: false,            // true = collect, don't alert per-event (the cron sends a digest)
  };
}

// inQuietHours(now, rules) — simple UTC hour window; wraps past midnight when start>end.
export function inQuietHours(now, rules) {
  const q = rules && rules.quietHours;
  if (!q || q.startHour == null || q.endHour == null) return false;
  const h = new Date(now).getUTCHours();
  const { startHour: s, endHour: e } = q;
  return s <= e ? (h >= s && h < e) : (h >= s || h < e);
}

// shouldAlert(event, rules, now) -> { alert, reason, suppressed }
// Decides whether a single event raises an alert. KEV / correlation / SLA / cert / drift events
// alert regardless of severity (when their toggle is on); finding events obey minSeverity.
// Digest mode and quiet hours suppress immediate delivery (reason records why).
export function shouldAlert(event, rules = defaultAlertRules(), now = Date.now()) {
  const r = { ...defaultAlertRules(), ...(rules || {}) };
  const no = (reason) => ({ alert: false, reason, suppressed: false });
  let want = false, reason = "";
  switch (event.kind) {
    case "kev": want = !!r.onKev; reason = "new KEV match"; break;
    case "correlation": want = !!r.onCorrelation; reason = "correlation chain"; break;
    case "sla": want = !!r.onSlaBreach; reason = "SLA breach"; break;
    case "drift": want = !!r.onDrift; reason = `record weakened (${event.severity})`; break;
    case "cert": {
      const days = Number(event.daysToExpiry);
      want = Number.isFinite(days) && days <= (r.certExpiryDays || 0); reason = `certificate expires in ${days}d`; break;
    }
    case "new": want = r.onNew && sevRank(event.severity) >= sevRank(r.minSeverity); reason = `new ${event.severity} finding`; break;
    case "worsened": want = r.onWorsened && sevRank(event.severity) >= sevRank(r.minSeverity); reason = `finding worsened to ${event.severity}`; break;
    case "changed": want = false; reason = "non-severity change"; break;
    case "resolved": want = !!r.onResolved; reason = "finding resolved"; break;
    default: want = false; reason = "unknown event";
  }
  if (!want) return no(reason ? "below policy: " + reason : "below policy");
  if (r.digest) return { alert: false, reason, suppressed: true };          // held for the digest
  if (inQuietHours(now, r)) return { alert: false, reason, suppressed: true }; // held until quiet hours end
  return { alert: true, reason, suppressed: false };
}
