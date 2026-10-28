// Cross-tool correlation (Deck D3). PURE — no DOM, no network, no graph writes.
//
// One tool sees "no MFA", another sees "impossible travel" — on the SAME person that
// is an account-takeover risk no single tool reports. This engine reads the graph's
// findings, uses core/resolve.js to tell when findings from different tools touch the
// same resolved host or identity, and returns correlation hits. It does NOT write to
// the graph (turning hits into INCIDENT entities is a separate, idempotent step), so
// it can never corrupt the graph.
import { resolveAssets, resolveIdentities, hostParts, canonIp, identityKeys } from "./resolve.js";
import { cyrb53 } from "./hash.js";
import { isSimulated } from "./posture.js";

const str = (v) => String(v == null ? "" : v).trim();
const lc = (v) => str(v).toLowerCase();
const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const DAY = 86400000;

const toMs = (v) => (typeof v === "number" ? v : (typeof v === "string" && v ? Date.parse(v) : NaN));

// ---- leg predicate helpers (compose into a finding predicate) -------------
const src = (...tools) => (f) => tools.includes(f.source);
const cat = (...cats) => (f) => cats.includes(f.category);
const sevAtLeast = (level) => (f) => (SEV_RANK[f.severity] || 0) >= (SEV_RANK[level] || 0);
const all = (...preds) => (f) => preds.every((p) => p(f));
const any = (...preds) => (f) => preds.some((p) => p(f));

// ---- the rule set. Each leg names tools + a predicate; a hit needs every leg
// matched by some finding on the same subject, within `window` if set. ----------
export const RULES = [
  {
    id: "account-takeover", subject: "identity", severity: "high",
    attack: ["T1078"], window: 30 * DAY,
    title: "Account-takeover risk",
    explain: "A sign-in anomaly on an account whose MFA or legacy-auth posture is weak — the classic account-takeover setup.",
    legs: [
      { id: "weak-auth", label: "Weak sign-in control (no/weak MFA or legacy auth)", when: any(all(src("caaudit"), cat("mfa", "legacy-auth")), all(src("vpnaudit"), cat("no_mfa", "legacy_client"))) },
      { id: "anomaly", label: "Sign-in anomaly (impossible travel, new country, brute force)", when: any(all(src("vpnaudit"), cat("impossible_travel", "new_country", "new_source", "brute_force", "spraying")), all(src("signins"), sevAtLeast("medium"))) },
    ],
  },
  {
    id: "leaver-active", subject: "identity", severity: "high",
    attack: ["T1078.004"], window: 90 * DAY,
    title: "Leaver still has access",
    explain: "HR marks this person a leaver, yet a sign-in or remote-access session is still happening on their account.",
    legs: [
      { id: "terminated", label: "Terminated in HR (offboarding verifier)", when: all(src("jml"), cat("leaver")) },
      { id: "still-active", label: "Sign-in, VPN or access-review activity after termination", when: any(src("vpnaudit"), src("signins"), all(src("accessreview"), cat("activity_after_termination", "leaver_enabled"))) },
    ],
  },
  {
    id: "priv-no-mfa", subject: "identity", severity: "high",
    attack: ["T1078"], window: 60 * DAY,
    title: "Privileged account without strong MFA",
    explain: "A standing-privileged account that also shows a weak MFA posture — a high-value target with a soft door.",
    legs: [
      { id: "privileged", label: "Standing or over-broad privilege", when: all(src("privaudit"), cat("standing-privilege", "privileged-use", "over-broad-policy", "role-sprawl")) },
      { id: "weak-mfa", label: "Weak MFA / legacy auth", when: any(all(src("caaudit"), cat("mfa", "legacy-auth")), all(src("vpnaudit"), cat("no_mfa"))) },
    ],
  },
  {
    id: "exploit-exposed-host", subject: "asset", severity: "critical",
    attack: ["T1190"], window: 60 * DAY,
    title: "Exploitable vulnerability on an internet-exposed host",
    explain: "A high/known-exploited vulnerability on a host that is also internet-exposed (RDP/SMB/SSH or a takeover-prone record).",
    legs: [
      { id: "vuln", label: "High / known-exploited vulnerability", when: any(all(src("vulnimport"), sevAtLeast("high")), (f) => f.kev) },
      { id: "exposed", label: "Internet-exposed service or record", when: any(all(src("netexposure"), cat("rdp", "smb", "ssh", "segmentation")), all(src("domainguard"), cat("takeover"))) },
    ],
  },
  {
    id: "exposed-no-backup", subject: "asset", severity: "high",
    attack: ["T1486"], window: 90 * DAY,
    title: "Exposed host with no sound backup",
    explain: "An internet-exposed host that also has a backup gap — if it is hit, recovery is not assured.",
    legs: [
      { id: "exposed", label: "Internet-exposed service", when: all(src("netexposure"), cat("rdp", "smb", "ssh", "segmentation")) },
      { id: "backup-gap", label: "Backup gap (unprotected, failing jobs, no restore test)", when: all(src("backupready"), cat("unprotected", "job-failures", "restore-testing", "immutability")) },
    ],
  },
  {
    // A live, unrotated machine credential that ALSO carries standing privilege or broad
    // trust — a key an attacker can use right now. Keyed on the IDENTITY (the service
    // principal), because that is the subject both nhi and privaudit resolve to. (The old
    // asset-keyed "leaked-secret" rule could never co-locate — nhi findings are IDENTITY,
    // code/IaC secret findings are host/repo — and named tools that never sink.)
    id: "live-priv-cred", subject: "identity", severity: "critical",
    attack: ["T1552.001", "T1078.004"], window: 60 * DAY,
    title: "Privileged machine credential that is live and unrotated",
    explain: "A non-human/service credential that is unrotated, expiring or over-used AND tied to standing privilege or broad cross-account trust — a working key with power behind it.",
    legs: [
      { id: "stale-cred", label: "Unrotated / overdue / over-used machine credential", when: all(src("nhi"), cat("rotation", "expiry", "usage")) },
      { id: "privileged", label: "Standing privilege or broad trust on the same principal", when: any(all(src("nhi"), cat("privilege")), all(src("privaudit"), cat("non-human-privilege", "standing-privilege", "cross-account-trust"))) },
    ],
  },
  {
    id: "brute-force-success", subject: "identity", severity: "critical",
    attack: ["T1110"], window: 14 * DAY,
    title: "Password attack followed by a successful sign-in",
    explain: "A password-spray or brute-force campaign against an account and a confirmed credential-stuffing success on that same account — the attack landed.",
    legs: [
      { id: "attempt", label: "Password spray / brute force against the account", when: any(all(src("vpnaudit"), cat("brute_force", "spraying")), all(src("signins"), cat("password_spray", "brute_force"))) },
      { id: "success", label: "Confirmed credential-stuffing / brute-force success", when: all(src("signins"), cat("cred_stuffing_success")) },
    ],
  },
  {
    id: "oauth-overscope", subject: "identity", severity: "high",
    attack: ["T1528"], window: 90 * DAY,
    title: "High-scope OAuth grant by a weakly-protected account",
    explain: "An account consented to a high-privilege OAuth application while its own sign-in control (MFA / legacy auth) is weak — a token-theft and consent-phishing exposure.",
    legs: [
      { id: "grant", label: "High-scope OAuth application grant", when: all(src("oauthgov"), cat("oauth")) },
      { id: "weak-auth", label: "Weak MFA / legacy auth or risky sign-in on the same account", when: any(all(src("caaudit"), cat("mfa", "legacy-auth")), all(src("signins"), sevAtLeast("high"))) },
    ],
  },
  {
    id: "domain-takeover", subject: "asset", severity: "high",
    attack: ["T1584.001"], window: 90 * DAY,
    title: "Takeover-prone domain we still rely on",
    explain: "A domain or DNS record at risk of hostile takeover (dangling record, lapsed delegation) that we still serve or hold certificates / transport posture for — a subdomain-takeover foothold.",
    legs: [
      { id: "takeover", label: "Dangling / takeover-prone DNS record", when: all(src("domainguard"), cat("takeover")) },
      { id: "still-ours", label: "Still served by our certificates or exposed transport", when: any(all(src("tlsfleet"), cat("certificate lifecycle", "transport security")), all(src("netexposure"), cat("tls", "certificate", "external exposure"))) },
    ],
  },
  {
    id: "beacon-exposed", subject: "asset", severity: "high",
    attack: ["T1071"], window: 14 * DAY,
    title: "C2 beaconing from an internet-exposed host",
    explain: "A host showing command-and-control DNS behaviour (beaconing, DGA, tunnelling) that is also internet-exposed — a likely foothold already communicating out.",
    legs: [
      { id: "c2", label: "Beaconing / DGA / DNS-tunnel behaviour", when: all(src("dnshunt"), cat("beacon", "dga", "tunnel")) },
      { id: "exposed", label: "Internet-exposed service", when: all(src("netexposure"), cat("rdp", "smb", "ssh", "segmentation", "external exposure")) },
    ],
  },
];

// ---- subject indexing: map a finding's referenced asset/identity names to the
// resolved cluster they belong to. ------------------------------------------------
function buildIndex(entities) {
  const assetClusters = resolveAssets(entities);
  const idRes = resolveIdentities(entities);
  const idClusters = idRes.clusters;

  const assetIdToKey = new Map();
  assetClusters.forEach((c) => c.members.forEach((id) => assetIdToKey.set(id, c.key)));
  const idIdToKey = new Map();
  idClusters.forEach((c) => c.members.forEach((id) => idIdToKey.set(id, c.key)));

  const assetNameKey = new Map(); // lookup string -> cluster key
  const idNameKey = new Map();
  for (const e of entities) {
    if (assetIdToKey.has(e.id)) {
      const ck = assetIdToKey.get(e.id), p = hostParts(e.name);
      assetNameKey.set(p.key, ck);
      if (p.kind === "ip") assetNameKey.set(canonIp(e.name), ck);
    }
    if (idIdToKey.has(e.id)) {
      const ck = idIdToKey.get(e.id), k = identityKeys(e.name, e.data || {});
      for (const v of [k.emailKey, k.upnKey, k.samKey]) if (v) idNameKey.set(v, ck);
      idNameKey.set(lc(e.name), ck);
    }
  }
  const nameMap = new Map();
  assetClusters.forEach((c) => nameMap.set("a:" + c.key, c.name));
  idClusters.forEach((c) => nameMap.set("i:" + c.key, c.name));
  return { assetNameKey, idNameKey, nameMap };
}

// Which cluster keys (per type) does a finding concern?
function subjectsOf(f, idx) {
  const assets = new Set(), identities = new Set();
  for (const raw of f.assetNames) {
    const name = str(raw); if (!name) continue;
    const hk = hostParts(name).key;
    if (idx.assetNameKey.has(hk)) assets.add(idx.assetNameKey.get(hk));
    const ik = identityKeys(name, {});
    for (const v of [ik.emailKey, ik.upnKey, ik.samKey, lc(name)]) if (v && idx.idNameKey.has(v)) identities.add(idx.idNameKey.get(v));
  }
  return { assets: [...assets], identities: [...identities] };
}

// ---- main ------------------------------------------------------------------------
// correlate(entities, { now }) -> hits[], each:
//   { ruleId, title, severity, attack, subjectType, subjectKey, subjectName,
//     explanation, legs:[{ id, label, findingId, findingTitle }], window, span }
const CLOSED = new Set(["resolved", "closed"]);
export function correlate(entities, opts = {}) {
  const ents = entities || [];
  const idx = buildIndex(ents);

  // finding views + their subjects
  const views = [];
  for (const e of ents) {
    if (e.type !== "FINDING" && e.type !== "VULNERABILITY") continue;
    // a fixed / false-positive / closed finding is no longer a leg of anything, and sample data never is
    if (CLOSED.has(lc(e.status)) || isSimulated(e)) continue;
    const d = e.data || {};
    const tags = e.tags || [];
    const title = str(e.name).replace(/\s*\([a-z0-9_-]+:[^)]*\)\s*$/i, ""); // strip "(tool:key)"
    const f = {
      id: e.id, title, source: str(e.source || d.tool), category: lc(d.category), severity: lc(e.severity),
      tags, ts: toMs(e.updatedAt) || toMs(e.createdAt) || 0, assetNames: Array.isArray(d.assets) ? d.assets : [],
      kev: tags.includes("kev") || /\bkev\b|known[- ]exploited/i.test(title) || !!d.kev,
    };
    f.subjects = subjectsOf(f, idx);
    views.push(f);
  }

  // group finding views by subject, per type
  const byAsset = new Map(), byId = new Map();
  const push = (map, key, f) => { if (!map.has(key)) map.set(key, []); map.get(key).push(f); };
  for (const f of views) { for (const k of f.subjects.assets) push(byAsset, k, f); for (const k of f.subjects.identities) push(byId, k, f); }

  const hits = [];
  for (const rule of RULES) {
    const groups = rule.subject === "asset" ? byAsset : byId;
    const prefix = rule.subject === "asset" ? "a:" : "i:";
    for (const [subjectKey, findings] of groups) {
      // Order findings deterministically (newest first, id tiebreak) so leg selection, the time-window
      // check and the emitted evidence ids never depend on graph iteration order.
      const findingsSorted = findings.slice().sort((a, b) => (b.ts - a.ts) || String(a.id).localeCompare(String(b.id)));
      // Each leg's candidate findings (newest-first, id tiebreak — inherited from findingsSorted).
      const perLeg = rule.legs.map((leg) => findingsSorted.filter((f) => leg.when(f)));
      if (perLeg.some((list) => list.length === 0)) continue; // a leg with no evidence => no hit
      let matched = null;
      if (!rule.window) {
        // No time constraint: newest finding per leg.
        matched = rule.legs.map((leg, i) => ({ leg, f: perLeg[i][0] }));
      } else {
        // Windowed rule: find the MOST RECENT window [r-W, r] of width W that holds, for EVERY
        // leg, at least one TIMESTAMPED finding, then take the newest in-window finding per leg.
        // Searching every candidate (not just the newest) means extra corroborating evidence on
        // one leg can no longer push a valid in-window chain out of view (fixes the false
        // negative), and a leg whose only evidence is untimestamped cannot satisfy a time-boxed
        // rule — so two findings of unknown relative time never correlate (fixes the false
        // positive from the old times.length>=2 guard).
        const W = rule.window;
        const anchors = [];
        for (const list of perLeg) for (const f of list) if (f.ts > 0) anchors.push(f.ts);
        anchors.sort((a, b) => b - a); // newest first => most recent feasible window wins
        for (const r of anchors) {
          const lo = r - W;
          const pick = perLeg.map((list) => list.find((f) => f.ts > 0 && f.ts >= lo && f.ts <= r));
          if (pick.every(Boolean)) { matched = rule.legs.map((leg, i) => ({ leg, f: pick[i] })); break; }
        }
        if (!matched) continue; // no in-window combination exists
      }
      const ts = matched.map((m) => m.f.ts).filter((t) => t > 0);
      const span = ts.length >= 2 ? Math.max(...ts) - Math.min(...ts) : 0;
      hits.push({
        ruleId: rule.id, title: rule.title, severity: rule.severity, attack: rule.attack.slice(),
        subjectType: rule.subject, subjectKey, subjectName: idx.nameMap.get(prefix + subjectKey) || subjectKey,
        explanation: rule.explain, window: rule.window || null, span,
        legs: matched.map((m) => ({ id: m.leg.id, label: m.leg.label, findingId: m.f.id, findingTitle: m.f.title })),
      });
    }
  }
  hits.sort((a, b) => (SEV_RANK[b.severity] || 0) - (SEV_RANK[a.severity] || 0) || a.ruleId.localeCompare(b.ruleId) || String(a.subjectKey).localeCompare(String(b.subjectKey)));
  return hits;
}

// ---- INCIDENT materialization -----------------------------------------------------
// Turn correlation hits into graph records so a chain becomes an ownable, trackable
// INCIDENT (not just a live read). PURE and idempotent: ids are deterministic (one
// incident per rule+subject) and timestamps are derived from the CONTRIBUTING findings
// already in the graph — createdAt = when the earliest leg appeared (SLA clock), updatedAt
// = when the latest leg last changed — so an unchanged chain produces a byte-identical
// record that GraphDO's wins() treats as a tie (zero churn), while a chain whose evidence
// moved strictly wins. The caller decides whether/when to write the result to the graph.
const PRIORITY = { critical: "p1", high: "p2", medium: "p3", low: "p4", info: "p4" };
export function incidentId(ruleId, subjectType, subjectKey) {
  return "inc" + cyrb53(str(ruleId) + "|" + str(subjectType) + ":" + str(subjectKey));
}

// materializeIncidents(hits, entities, { now }) -> { entities:[INCIDENT...], relationships:[FINDING -evidence_for-> INCIDENT] }
export function materializeIncidents(hits, entities, opts = {}) {
  const nowMs = Number.isFinite(opts.now) ? opts.now : NaN;
  const iso = (ms) => new Date(Number.isFinite(ms) ? ms : 0).toISOString();
  // finding id -> { created, updated } in ms (stable graph data drives the incident clock)
  const ftimes = new Map();
  for (const e of (entities || [])) {
    if (e.type !== "FINDING" && e.type !== "VULNERABILITY") continue;
    const u = toMs(e.updatedAt), c = toMs(e.createdAt);
    ftimes.set(e.id, { created: Number.isFinite(c) ? c : (Number.isFinite(u) ? u : nowMs), updated: Number.isFinite(u) ? u : (Number.isFinite(c) ? c : nowMs) });
  }
  const outEnts = [], outRels = [];
  for (const h of (hits || [])) {
    const id = incidentId(h.ruleId, h.subjectType, h.subjectKey);
    const legTimes = h.legs.map((l) => ftimes.get(l.findingId)).filter(Boolean);
    const createdMs = legTimes.length ? Math.min(...legTimes.map((t) => t.created)) : nowMs;
    const updatedMs = legTimes.length ? Math.max(...legTimes.map((t) => t.updated)) : nowMs;
    const createdAt = iso(createdMs), updatedAt = iso(updatedMs);
    outEnts.push({
      id, type: "INCIDENT", name: `${h.title}: ${h.subjectName}`,
      severity: h.severity, status: "open", source: "correlate",
      createdAt, updatedAt,
      data: {
        title: h.title, phase: "identification", priority: PRIORITY[h.severity] || "p3",
        summary: h.explanation, rule: h.ruleId, attack: (h.attack || []).slice(),
        subjectType: h.subjectType, subjectName: h.subjectName, window: h.window || null, span: h.span || 0,
        legs: h.legs.map((l) => ({ id: l.id, label: l.label, findingId: l.findingId, findingTitle: l.findingTitle })),
      },
    });
    // Each contributing finding is evidence_for the incident. createdAt tracks the finding's
    // own first-seen (stable) so the relationship is a tie on an unchanged re-run.
    for (const l of h.legs) {
      const ft = ftimes.get(l.findingId);
      outRels.push({ id: "r" + cyrb53(str(l.findingId) + "|evidence_for|" + id), fromId: str(l.findingId), toId: id, type: "evidence_for", createdAt: iso(ft ? ft.created : createdMs) });
    }
  }
  return { entities: outEnts, relationships: outRels };
}
